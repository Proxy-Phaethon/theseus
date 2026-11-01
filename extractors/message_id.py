from email import policy
from email.parser import BytesParser
from pathlib import Path
import hashlib
import re

from core.packets import Packet, PacketStatus

MESSAGE_ID_PATTERN = re.compile(
    r"^<([^<>\s@]+)@([^<>\s@]+)>$"
)

def _parse_message_id(value):
    """
    Validate and split a Message-ID into its local and domain components.
    """
    if not isinstance(value, str):
        raise ValueError("Message-ID must be a string.")

    candidate = value.strip()

    if not candidate:
        raise ValueError("Message-ID is empty.")

    match = MESSAGE_ID_PATTERN.fullmatch(candidate)

    if not match:
        raise ValueError("Invalid Message-ID format.")

    local_part, domain = match.groups()

    return {
        "message_id": candidate,
        "local_part": local_part,
        "domain": domain,
        "normalized": f"<{local_part}@{domain.lower()}>",
    }


def _parse_email_source(source):
    message = BytesParser(policy=policy.default).parsebytes(source)

    if not list(message.raw_items()):
        raise ValueError("No email headers were found.")

    message_ids = message.get_all("Message-ID", [])

    if not message_ids:
        raise ValueError("Email source does not contain a Message-ID header.")

    if len(message_ids) > 1:
        raise ValueError("Email source contains multiple Message-ID headers.")

    return str(message_ids[0])


def _hash_source(source):
    return {
        "md5": hashlib.md5(source).hexdigest(),
        "sha1": hashlib.sha1(source).hexdigest(),
        "sha256": hashlib.sha256(source).hexdigest(),
    }


def messageidextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="message_id",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError("Message-ID input must be a non-empty string.")

        candidate = value.strip()

        source_type = "message_id"
        source_path = None
        source_hashes = None

        # Raw email source.
        if "\n" in candidate or "\r" in candidate:
            raw_source = candidate.encode("utf-8", errors="replace")
            candidate = _parse_email_source(raw_source)
            source_type = "raw_email"
            source_hashes = _hash_source(raw_source)

        else:
            # Check whether the input is an existing .eml file.
            path = Path(candidate)

            try:
                is_file = path.is_file()
            except OSError:
                is_file = False

            if is_file:
                if path.suffix.lower() != ".eml":
                    raise ValueError(
                        "Only .eml files are supported as email source files."
                    )

                raw_source = path.read_bytes()
                candidate = _parse_email_source(raw_source)

                source_type = "file"
                source_path = str(path.resolve())
                source_hashes = _hash_source(raw_source)

        parsed = _parse_message_id(candidate)

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "hashes": source_hashes,
            },
            **parsed,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="MESSAGE_ID_SOURCE_NOT_FOUND",
            message=str(exc),
            component="extractors.message_id",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="MESSAGE_ID_PERMISSION_DENIED",
            message="Permission denied while reading the email source.",
            component="extractors.message_id",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="MESSAGE_ID_INVALID_INPUT",
            message=str(exc),
            component="extractors.message_id",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="MESSAGE_ID_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.message_id",
        )

    return result