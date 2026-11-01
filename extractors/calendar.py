from pathlib import Path
import hashlib

from icalendar import Calendar, Event, Todo, Journal, Alarm
from icalendar.cal import Component

from core.packets import Packet, PacketStatus

SUPPORTED_COMPONENTS = {
    "VEVENT",
    "VTODO",
    "VJOURNAL",
    "VFREEBUSY",
    "VTIMEZONE",
}

IMPORTANT_PROPERTIES = {
    "UID",
    "SUMMARY",
    "DESCRIPTION",
    "LOCATION",
    "STATUS",
    "CLASS",
    "CATEGORIES",
    "URL",
    "DTSTART",
    "DTEND",
    "DUE",
    "DURATION",
    "CREATED",
    "LAST-MODIFIED",
    "DTSTAMP",
    "ORGANIZER",
    "ATTENDEE",
    "RECURRENCE-ID",
    "RRULE",
    "RDATE",
    "EXDATE",
    "SEQUENCE",
    "PRIORITY",
    "TRANSP",
    "GEO",
    "RELATED-TO",
    "ATTACH",
    "TRIGGER",
    "ACTION",
}

def _decode_value(value):
    """Convert iCalendar values into JSON-compatible representations."""
    if value is None:
        return None

    if hasattr(value, "dt"):
        return _decode_value(value.dt)

    if hasattr(value, "to_ical"):
        try:
            return value.to_ical().decode("utf-8", errors="replace")
        except Exception:
            pass

    if hasattr(value, "items"):
        try:
            return {
                str(key): _decode_value(item)
                for key, item in value.items()
            }
        except Exception:
            pass

    if isinstance(value, (list, tuple)):
        return [_decode_value(item) for item in value]

    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, (str, int, float, bool)):
        return value

    return str(value)

def _extract_parameters(value):
    params = getattr(value, "params", {})

    return {
        str(key): _decode_value(item)
        for key, item in params.items()
    }

def _extract_properties(component):
    properties = {}

    for name in component.keys():
        values = component.getall(name)

        extracted = []

        for value in values:
            extracted.append({
                "value": _decode_value(value),
                "parameters": _extract_parameters(value),
            })

        properties[str(name)] = extracted

    return properties

def _extract_component(component):
    component_type = component.name

    return {
        "type": component_type,
        "properties": _extract_properties(component),
        "alarms": [
            _extract_component(alarm)
            for alarm in component.subcomponents
            if alarm.name == "VALARM"
        ],
    }

def _extract_timezone(component):
    return {
        "tzid": _decode_value(component.get("TZID")),
        "properties": _extract_properties(component),
        "observances": [
            _extract_component(child)
            for child in component.subcomponents
        ],
    }

def _extract_components(calendar):
    components = {
        "events": [],
        "tasks": [],
        "journals": [],
        "freebusy": [],
        "timezones": [],
        "other": [],
    }

    mapping = {
        "VEVENT": "events",
        "VTODO": "tasks",
        "VJOURNAL": "journals",
        "VFREEBUSY": "freebusy",
        "VTIMEZONE": "timezones",
    }

    for component in calendar.subcomponents:
        component_type = component.name

        if component_type == "VTIMEZONE":
            components["timezones"].append(
                _extract_timezone(component)
            )

        elif component_type in mapping:
            components[mapping[component_type]].append(
                _extract_component(component)
            )

        else:
            components["other"].append(
                _extract_component(component)
            )

    return components

def _extract_calendar_properties(calendar):
    properties = {}

    for name in calendar.keys():
        values = calendar.getall(name)

        properties[str(name)] = [
            {
                "value": _decode_value(value),
                "parameters": _extract_parameters(value),
            }
            for value in values
        ]

    return properties

def _hash_source(source):
    return {
        "md5": hashlib.md5(source).hexdigest(),
        "sha1": hashlib.sha1(source).hexdigest(),
        "sha256": hashlib.sha256(source).hexdigest(),
    }

def calendarextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="calendar",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "Calendar input must be a non-empty string."
            )

        candidate = value.strip()

        source_type = "raw_icalendar"
        source_path = None

        if "\n" in candidate or "\r" in candidate:
            raw_source = candidate.encode("utf-8", errors="replace")

        else:
            path = Path(candidate)

            try:
                is_file = path.is_file()
            except OSError:
                is_file = False

            if not is_file:
                raise FileNotFoundError(
                    "Calendar source file was not found."
                )

            if path.suffix.lower() != ".ics":
                raise ValueError(
                    "Only .ics calendar files are supported."
                )

            raw_source = path.read_bytes()
            source_type = "file"
            source_path = str(path.resolve())

        calendar = Calendar.from_ical(raw_source)

        if calendar.name != "VCALENDAR":
            raise ValueError(
                "Input is not a valid VCALENDAR component."
            )

        components = _extract_components(calendar)

        component_count = sum(
            len(items)
            for items in components.values()
        )

        if component_count == 0:
            raise ValueError(
                "Calendar contains no extractable components."
            )

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size_bytes": len(raw_source),
                "hashes": _hash_source(raw_source),
            },
            "calendar": {
                "properties": _extract_calendar_properties(calendar),
                "components": components,
                "component_count": component_count,
                "counts": {
                    name: len(items)
                    for name, items in components.items()
                },
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CALENDAR_SOURCE_NOT_FOUND",
            message=str(exc),
            component="extractors.calendar",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CALENDAR_PERMISSION_DENIED",
            message="Permission denied while reading the calendar source.",
            component="extractors.calendar",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CALENDAR_INVALID_INPUT",
            message=str(exc),
            component="extractors.calendar",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CALENDAR_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.calendar",
        )

    return result