from pathlib import Path
import hashlib
import mailbox
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from core.packets import Packet, PacketStatus

MAX_MESSAGES = 1000

def _hash_bytes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def _hash_file(path: Path) -> dict:
    algorithms = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for algorithm in algorithms.values():
                algorithm.update(chunk)

    return {
        name: algorithm.hexdigest()
        for name, algorithm in algorithms.items()
    }

def _decode_header(value):
    if value is None:
        return None

    try:
        from email.header import decode_header, make_header

        return str(make_header(decode_header(str(value))))
    except (ValueError, LookupError, UnicodeError):
        return str(value)

def _parse_date(value):
    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(value)

        if parsed.tzinfo is None:
            return parsed.isoformat()

        return parsed.astimezone(timezone.utc).isoformat()

    except (TypeError, ValueError, OverflowError):
        return None

def _extract_addresses(message, header_name):
    values = message.get_all(header_name, [])
    addresses = []

    for display_name, address in getaddresses(values):
        addresses.append({
            "display_name": display_name or None,
            "address": address or None,
        })

    return addresses

def _extract_authentication(headers: dict) -> dict:
    authentication = {}

    relevant_headers = {
        "authentication-results",
        "received-spf",
        "dkim-signature",
        "arc-authentication-results",
        "arc-seal",
        "arc-message-signature",
    }

    for name, values in headers.items():
        if name.lower() in relevant_headers:
            authentication[name.lower()] = values

    return authentication

def _extract_headers(message) -> dict:
    headers = {}

    for name, value in message.items():
        decoded = _decode_header(value)
        headers.setdefault(name.lower(), []).append(decoded)

    return headers

def _extract_mime_part(part, index: int) -> dict:
    payload = part.get_payload(decode=True)

    if payload is None:
        payload = b""

    filename = part.get_filename()

    return {
        "index": index,
        "content_type": part.get_content_type(),
        "content_disposition": part.get_content_disposition(),
        "content_id": part.get("Content-ID"),
        "filename": _decode_header(filename),
        "content_transfer_encoding": part.get(
            "Content-Transfer-Encoding"
        ),
        "size_bytes": len(payload),
        "is_attachment": part.get_content_disposition() == "attachment"
        or filename is not None,
        "hashes": _hash_bytes(payload) if payload else None,
    }

def _extract_body(message) -> dict:
    body = {
        "plain_text": [],
        "html": [],
        "other_parts": [],
    }

    mime_parts = []
    attachment_count = 0

    parts = (
        message.walk()
        if message.is_multipart()
        else [message]
    )

    for index, part in enumerate(parts):
        if part.is_multipart():
            continue

        mime_parts.append(
            _extract_mime_part(part, index)
        )

        if (
            part.get_content_disposition() == "attachment"
            or part.get_filename()
        ):
            attachment_count += 1
            continue

        content_type = part.get_content_type()

        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError, ValueError):
            content = part.get_payload(decode=True)

        if isinstance(content, bytes):
            content = content.decode(
                part.get_content_charset() or "utf-8",
                errors="replace",
            )

        if content_type == "text/plain":
            body["plain_text"].append(content)

        elif content_type == "text/html":
            body["html"].append(content)

        else:
            body["other_parts"].append({
                "content_type": content_type,
                "size_bytes": len(
                    content.encode("utf-8")
                    if isinstance(content, str)
                    else content or b""
                ),
            })

    return {
        "body": body,
        "mime_parts": mime_parts,
        "attachment_count": attachment_count,
    }

def _extract_message(message, index: int = 0) -> dict:
    headers = _extract_headers(message)
    body_data = _extract_body(message)

    received = [
        _decode_header(value)
        for value in message.get_all("Received", [])
    ]

    return {
        "index": index,
        "headers": headers,
        "message": {
            "subject": _decode_header(message.get("Subject")),
            "message_id": message.get("Message-ID"),
            "in_reply_to": message.get("In-Reply-To"),
            "references": message.get_all("References", []),
            "date": _parse_date(message.get("Date")),
            "from": _extract_addresses(message, "From"),
            "sender": _extract_addresses(message, "Sender"),
            "reply_to": _extract_addresses(message, "Reply-To"),
            "to": _extract_addresses(message, "To"),
            "cc": _extract_addresses(message, "Cc"),
            "bcc": _extract_addresses(message, "Bcc"),
            "return_path": message.get("Return-Path"),
        },
        "routing": {
            "received": received,
            "received_count": len(received),
        },
        "authentication": _extract_authentication(headers),
        **body_data,
    }

def _extract_eml(data: bytes) -> dict:
    message = BytesParser(
        policy=policy.default
    ).parsebytes(data)

    return {
        "format": "EML",
        "message_count": 1,
        "messages": [
            _extract_message(message)
        ],
    }

def _extract_mbox(path: Path) -> dict:
    mailbox_file = mailbox.mbox(
        str(path),
        create=False,
    )

    try:
        message_count = len(mailbox_file)

        if message_count > MAX_MESSAGES:
            raise ValueError(
                f"Mailbox contains more than {MAX_MESSAGES} messages."
            )

        messages = []

        for index, message in enumerate(mailbox_file):
            messages.append(
                _extract_message(message, index)
            )

        return {
            "format": "MBOX",
            "message_count": message_count,
            "messages": messages,
        }

    finally:
        mailbox_file.close()

def emailextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="email",
        status=PacketStatus.RUNNING,
    )

    try:
        input_value = packet.input

        if not isinstance(input_value, str) or not input_value.strip():
            raise ValueError("Email input must be a non-empty string.")

        candidate = input_value.strip()

        # Detect raw email source before filesystem operations.
        if "\n" in candidate or "\r" in candidate:
            raw_data = candidate.encode("utf-8")

            if not (
                b"From:" in raw_data
                or b"Received:" in raw_data
                or b"Message-ID:" in raw_data
            ):
                raise ValueError(
                    "Input does not contain recognisable email headers."
                )

            email_data = _extract_eml(raw_data)
            file_data = None

        else:
            path = Path(candidate).expanduser()

            if not path.exists():
                raise FileNotFoundError(
                    f"Email file not found: {path}"
                )

            if not path.is_file():
                raise ValueError("Input must be a file.")

            extension = path.suffix.lower()

            if extension == ".eml":
                raw_data = path.read_bytes()
                email_data = _extract_eml(raw_data)

            elif extension == ".mbox":
                email_data = _extract_mbox(path)

            else:
                raise ValueError(
                    f"Unsupported email file extension: {extension}"
                )

            file_data = {
                "name": path.name,
                "extension": extension,
                "absolute_path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "hashes": _hash_file(path),
            }

        result.data = {
            "file": file_data,
            "email": email_data,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="EMAIL_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.email",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="EMAIL_ACCESS_DENIED",
            message=str(exc),
            component="extractors.email",
        )
        result.status = PacketStatus.FAILED

    except (OSError, mailbox.Error) as exc:
        result.add_error(
            code="EMAIL_READ_FAILED",
            message=str(exc),
            component="extractors.email",
        )
        result.status = PacketStatus.FAILED

    except ValueError as exc:
        result.add_error(
            code="INVALID_EMAIL_INPUT",
            message=str(exc),
            component="extractors.email",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="EMAIL_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.email",
        )
        result.status = PacketStatus.FAILED

    return result