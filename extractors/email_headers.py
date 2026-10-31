from datetime import timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
import hashlib

from core.packets import Packet, PacketStatus

AUTHENTICATION_HEADERS = {
    "authentication-results",
    "received-spf",
    "dkim-signature",
    "arc-authentication-results",
    "arc-message-signature",
    "arc-seal",
}

ADDRESS_HEADERS = {
    "from",
    "sender",
    "reply-to",
    "to",
    "cc",
    "bcc",
    "resent-from",
    "resent-to",
    "resent-cc",
    "resent-bcc",
}

IMPORTANT_HEADERS = {
    "subject",
    "date",
    "message-id",
    "in-reply-to",
    "references",
    "return-path",
    "received",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
}

def _decode_header(value):
    """Return the decoded representation of a header value."""
    try:
        return str(value)
    except Exception:
        return str(value).encode("utf-8", errors="replace").decode("utf-8")

def _extract_addresses(message):
    addresses = {}

    for header in ADDRESS_HEADERS:
        values = message.get_all(header, [])

        if not values:
            addresses[header] = []
            continue

        parsed = []

        for name, address in getaddresses(values):
            parsed.append({
                "display_name": name or None,
                "address": address or None,
            })

        addresses[header] = parsed

    return addresses

def _extract_date(message):
    value = message.get("Date")

    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(str(value))

        if parsed is None:
            return None

        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)

        return parsed.isoformat()

    except (TypeError, ValueError, OverflowError):
        return None

def _extract_headers(message):
    headers = []

    for name, value in message.raw_items():
        headers.append({
            "name": name,
            "normalized_name": name.lower(),
            "value": _decode_header(value),
        })

    return headers

def _extract_authentication(message):
    result = {}

    for name in AUTHENTICATION_HEADERS:
        values = message.get_all(name, [])

        if values:
            result[name] = [_decode_header(value) for value in values]

    return result

def _extract_received(message):
    values = message.get_all("Received", [])

    return [
        _decode_header(value)
        for value in values
    ]

def _extract_important_headers(message):
    result = {}

    for name in IMPORTANT_HEADERS:
        values = message.get_all(name, [])

        if not values:
            result[name] = None
        elif len(values) == 1:
            result[name] = _decode_header(values[0])
        else:
            result[name] = [
                _decode_header(value)
                for value in values
            ]

    return result

def _parse_source(source):
    return BytesParser(policy=policy.default).parsebytes(source)

def emailheadersextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="email_headers",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError("Email header input must be a non-empty string.")

        source = value.strip()
        file_path = None
        file_hashes = None

        # Multiline input is treated as raw email source.
        if "\n" in source or "\r" in source:
            raw_source = source.encode("utf-8", errors="replace")

        else:
            candidate = Path(source)

            try:
                is_file = candidate.is_file()
            except OSError:
                is_file = False

            if not is_file:
                raise FileNotFoundError(
                    "Input is neither raw email source nor an accessible file."
                )

            if candidate.suffix.lower() != ".eml":
                raise ValueError("Email header extraction supports .eml files only.")

            raw_source = candidate.read_bytes()
            file_path = str(candidate.resolve())

            file_hashes = {
                "md5": hashlib.md5(raw_source).hexdigest(),
                "sha1": hashlib.sha1(raw_source).hexdigest(),
                "sha256": hashlib.sha256(raw_source).hexdigest(),
            }

        message = _parse_source(raw_source)

        if not list(message.raw_items()):
            raise ValueError("No email headers were found in the supplied input.")

        headers = _extract_headers(message)

        result.data = {
            "source": {
                "type": "file" if file_path else "raw_email",
                "path": file_path,
                "size_bytes": len(raw_source),
                "hashes": file_hashes,
            },
            "headers": headers,
            "header_count": len(headers),
            "important_headers": _extract_important_headers(message),
            "addresses": _extract_addresses(message),
            "date_parsed": _extract_date(message),
            "received_chain": _extract_received(message),
            "authentication_headers": _extract_authentication(message),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="EMAIL_HEADERS_SOURCE_NOT_FOUND",
            message=str(exc),
            component="extractors.email_headers",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="EMAIL_HEADERS_PERMISSION_DENIED",
            message="Permission denied while reading the email source.",
            component="extractors.email_headers",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="EMAIL_HEADERS_INVALID_INPUT",
            message=str(exc),
            component="extractors.email_headers",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="EMAIL_HEADERS_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.email_headers",
        )

    return result