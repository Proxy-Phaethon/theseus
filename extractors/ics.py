from pathlib import Path
import hashlib

from icalendar import Calendar

from core.packets import Packet, PacketStatus

def _hash_file(path):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for digest in hashes.values():
                digest.update(chunk)

    return {
        name: digest.hexdigest()
        for name, digest in hashes.items()
    }

def _decode_value(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (list, tuple)):
        return [_decode_value(item) for item in value]

    if hasattr(value, "dt"):
        return _decode_value(value.dt)

    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass

    if hasattr(value, "to_ical"):
        try:
            return value.to_ical().decode("utf-8", errors="replace")
        except Exception:
            pass

    return str(value)

def _extract_properties(component):
    properties = {}

    for name in component.keys():
        values = component.getall(name)

        properties[str(name)] = [
            {
                "value": _decode_value(value),
                "parameters": {
                    str(key): _decode_value(parameter)
                    for key, parameter in getattr(value, "params", {}).items()
                },
            }
            for value in values
        ]

    return properties

def _extract_file_metadata(path):
    stat = path.stat()

    return {
        "name": path.name,
        "stem": path.stem,
        "extension": path.suffix.lower(),
        "absolute_path": str(path.resolve()),
        "parent_directory": str(path.parent.resolve()),
        "size_bytes": stat.st_size,
        "modified": stat.st_mtime,
        "accessed": stat.st_atime,
        "created": getattr(stat, "st_birthtime", None),
        "is_symlink": path.is_symlink(),
    }

def _extract_component_counts(calendar):
    counts = {}

    for component in calendar.subcomponents:
        name = component.name
        counts[name] = counts.get(name, 0) + 1

    return counts

def _extract_timezone_ids(calendar):
    identifiers = []

    for component in calendar.subcomponents:
        if component.name == "VTIMEZONE":
            tzid = component.get("TZID")

            if tzid is not None:
                identifiers.append(_decode_value(tzid))

    return identifiers

def icsextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="ics",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError("ICS input must be a non-empty file path.")

        path = Path(value.strip())

        if not path.exists():
            raise FileNotFoundError("ICS file was not found.")

        if not path.is_file():
            raise ValueError("ICS input must point to a regular file.")

        if path.suffix.lower() != ".ics":
            raise ValueError("Unsupported file extension. Expected .ics.")

        metadata = _extract_file_metadata(path)
        hashes = _hash_file(path)

        raw_source = path.read_bytes()
        calendar = Calendar.from_ical(raw_source)

        if calendar.name != "VCALENDAR":
            raise ValueError("File does not contain a VCALENDAR component.")

        properties = _extract_properties(calendar)
        component_counts = _extract_component_counts(calendar)

        result.data = {
            "file": {
                **metadata,
                "hashes": hashes,
            },
            "calendar": {
                "version": _decode_value(calendar.get("VERSION")),
                "product_id": _decode_value(calendar.get("PRODID")),
                "scale": _decode_value(calendar.get("CALSCALE")),
                "method": _decode_value(calendar.get("METHOD")),
                "name": _decode_value(calendar.get("X-WR-CALNAME")),
                "description": _decode_value(calendar.get("X-WR-CALDESC")),
                "timezone_ids": _extract_timezone_ids(calendar),
                "properties": properties,
                "component_counts": component_counts,
                "total_components": sum(component_counts.values()),
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ICS_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.ics",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ICS_PERMISSION_DENIED",
            message="Permission denied while reading the ICS file.",
            component="extractors.ics",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ICS_INVALID_INPUT",
            message=str(exc),
            component="extractors.ics",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ICS_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.ics",
        )

    return result