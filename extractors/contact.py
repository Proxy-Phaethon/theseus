from pathlib import Path
import hashlib
import re
from unittest import result

from core.packets import Packet, PacketStatus

EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?$",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(r"^\+?[0-9][0-9\s()./-]{2,24}$")

VCARD_PROPERTIES = {
    "FN",
    "N",
    "ORG",
    "TITLE",
    "TEL",
    "EMAIL",
    "ADR",
    "URL",
    "NOTE",
    "UID",
}

def _unfold_lines(source):
    """Join vCard continuation lines."""
    lines = []

    for line in source.splitlines():
        if line.startswith((" ", "\t")) and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)

    return lines

def _parse_property(line):
    if ":" not in line:
        return None

    name_and_params, value = line.split(":", 1)
    parts = name_and_params.split(";")

    name = parts[0].split(".")[-1].upper()
    params = {}

    for part in parts[1:]:
        if "=" in part:
            key, parameter_value = part.split("=", 1)
            params[key.upper()] = parameter_value.strip('"')

    return {
        "name": name,
        "parameters": params,
        "value": value,
    }

def _parse_vcard(source):
    lines = _unfold_lines(source)
    contacts = []
    current = None

    for line in lines:
        line = line.strip()

        if line.upper() == "BEGIN:VCARD":
            if current is not None:
                raise ValueError("Nested vCard entries are invalid.")

            current = {}
            continue

        if line.upper() == "END:VCARD":
            if current is None:
                raise ValueError("Unexpected END:VCARD.")

            contacts.append(current)
            current = None
            continue

        if current is None:
            continue

        prop = _parse_property(line)

        if not prop:
            continue

        name = prop["name"]

        if name not in VCARD_PROPERTIES:
            continue

        current.setdefault(name, []).append({
            "value": prop["value"],
            "parameters": prop["parameters"],
        })

    if current is not None:
        raise ValueError("Unterminated vCard entry.")

    if not contacts:
        raise ValueError("No valid vCard entries were found.")

    return contacts

def _extract_vcard_value(contact, name):
    values = contact.get(name, [])

    if not values:
        return None

    return values[0]["value"]

def _extract_vcard_contacts(source):
    parsed = _parse_vcard(source)
    contacts = []

    for entry in parsed:
        contacts.append({
            "full_name": _extract_vcard_value(entry, "FN"),
            "structured_name": _extract_vcard_value(entry, "N"),
            "organisation": _extract_vcard_value(entry, "ORG"),
            "title": _extract_vcard_value(entry, "TITLE"),
            "emails": entry.get("EMAIL", []),
            "phone_numbers": entry.get("TEL", []),
            "addresses": entry.get("ADR", []),
            "urls": entry.get("URL", []),
            "notes": entry.get("NOTE", []),
            "uid": _extract_vcard_value(entry, "UID"),
        })

    return contacts

def _hash_source(source):
    return {
        "md5": hashlib.md5(source).hexdigest(),
        "sha1": hashlib.sha1(source).hexdigest(),
        "sha256": hashlib.sha256(source).hexdigest(),
    }

def _extract_plain_contact(value):
    candidate = value.strip()

    if EMAIL_PATTERN.fullmatch(candidate):
        return {
            "type": "email",
            "value": candidate,
        }

    if PHONE_PATTERN.fullmatch(candidate):
        digits = re.sub(r"\D", "", candidate)

        if len(digits) < 7 or len(digits) > 15:
            raise ValueError("Phone number must contain between 7 and 15 digits.")

        return {
            "type": "phone",
            "value": candidate,
            "digits": digits,
        }

    raise ValueError(
        "Input is not a recognised email address, phone number, or vCard source."
    )


def contactextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="contact",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError("Contact input must be a non-empty string.")

        candidate = value.strip()

        # Raw vCard source.
        if "BEGIN:VCARD" in candidate.upper():
            raw_source = candidate.encode("utf-8", errors="replace")

            contacts = _extract_vcard_contacts(candidate)

            result.data = {
                "source": {
                    "type": "raw_vcard",
                    "path": None,
                    "hashes": _hash_source(raw_source),
                },
                "contacts": contacts,
                "contact_count": len(contacts),
            }

        else:
            path = Path(candidate)

            try:
                is_file = path.is_file()
            except OSError:
                is_file = False

            if is_file:
                if path.suffix.lower() != ".vcf":
                    raise ValueError("Only .vcf files are supported as contact files.")

                raw_source = path.read_bytes()
                source = raw_source.decode("utf-8-sig", errors="replace")
                contacts = _extract_vcard_contacts(source)

                result.data = {
                    "source": {
                        "type": "file",
                        "path": str(path.resolve()),
                        "hashes": _hash_source(raw_source),
                    },
                    "contacts": contacts,
                    "contact_count": len(contacts),
                }

            else:
                result.data = {
                    "source": {
                        "type": "direct_input",
                        "path": None,
                        "hashes": None,
                    },
                    "contact": _extract_plain_contact(candidate),
                }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONTACT_SOURCE_NOT_FOUND",
            message=str(exc),
            component="extractors.contact",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONTACT_PERMISSION_DENIED",
            message="Permission denied while reading the contact source.",
            component="extractors.contact",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONTACT_INVALID_INPUT",
            message=str(exc),
            component="extractors.contact",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONTACT_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.contact",
        )

    return result