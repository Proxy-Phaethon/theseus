import hashlib
import re

from pathlib import Path
from collections import Counter
from datetime import datetime

from core.packets import Packet, PacketStatus

MAX_FILE_SIZE = 50 * 1024 * 1024

# ISO 8601 timestamps
ISO_TIMESTAMP = re.compile(
    r"^\[?(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}"
    r"[T ]"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?"
    r")\]?"
)

# Common application log format
APP_LOG = re.compile(
    r"^(?:"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ][\d:.+-]+Z?)"
    r"\s+"
    r")?"
    r"(?:(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)"
    r"\s*[:\]]?\s+)?"
    r"(?:(?P<source>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+)?"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)

# Syslog-style message
SYSLOG = re.compile(
    r"^(?:<(?P<priority>\d{1,3})>)?"
    r"(?P<timestamp>"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<message>.*)$"
)

# Apache/Nginx access log
ACCESS_LOG = re.compile(
    r'^(?P<client>\S+)\s+'
    r'(?P<identity>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

LEVELS = {
    "TRACE",
    "DEBUG",
    "INFO",
    "NOTICE",
    "WARN",
    "WARNING",
    "ERROR",
    "CRITICAL",
    "FATAL",
}

def logextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="log",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be log text or a file path.")

        path = Path(source)
        source_type = "raw"
        source_path = None
        file_size = None

        if path.is_file():
            file_size = path.stat().st_size

            if file_size > MAX_FILE_SIZE:
                raise ValueError(
                    f"Log file exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            raw_bytes = path.read_bytes()

            try:
                raw = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "Log file is not valid UTF-8."
                ) from exc

            source_type = "file"
            source_path = str(path.resolve())
            source_hash = hashlib.sha256(raw_bytes).hexdigest()

        else:
            raw = str(source)

            if not raw.strip():
                raise ValueError("Log input is empty.")

            if len(raw.encode("utf-8")) > MAX_FILE_SIZE:
                raise ValueError(
                    f"Log input exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            source_hash = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

        if not raw.strip():
            raise ValueError("Log input is empty.")

        entries = []
        format_counts = Counter()
        level_counts = Counter()
        source_counts = Counter()
        invalid_lines = []

        for line_number, line in enumerate(
            raw.splitlines(),
            start=1,
        ):
            if not line.strip():
                continue

            entry = _parse_line(line, line_number)

            entries.append(entry)
            format_counts[entry["format"]] += 1

            if entry["level"]:
                level_counts[entry["level"]] += 1

            if entry["source"]:
                source_counts[entry["source"]] += 1

            if entry["format"] == "unstructured":
                invalid_lines.append(line_number)

        timestamps = [
            entry["timestamp"]
            for entry in entries
            if entry["timestamp"]
        ]

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size": file_size,
                "sha256": source_hash,
            },
            "log": {
                "entries": entries,
                "statistics": {
                    "total_lines": len(raw.splitlines()),
                    "parsed_entries": len(entries),
                    "timestamped_entries": len(timestamps),
                    "unstructured_entries": len(invalid_lines),
                    "unique_sources": len(source_counts),
                    "formats": dict(format_counts),
                    "levels": dict(level_counts),
                    "sources": dict(source_counts),
                    "first_timestamp": (
                        timestamps[0] if timestamps else None
                    ),
                    "last_timestamp": (
                        timestamps[-1] if timestamps else None
                    ),
                },
                "unstructured_lines": invalid_lines,
            },
        }

        result.status = (
            PacketStatus.PARTIAL_SUCCESS
            if invalid_lines
            else PacketStatus.SUCCESS
        )

        if invalid_lines:
            result.add_error(
                code="LOG_UNSTRUCTURED_LINES",
                message=(
                    f"{len(invalid_lines)} lines could not be "
                    "matched to a recognised log format."
                ),
                component="extractors.log",
            )

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="LOG_FILE_NOT_FOUND",
            message="The specified log file could not be found.",
            component="extractors.log",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="LOG_PERMISSION_DENIED",
            message="Permission denied while reading the log file.",
            component="extractors.log",
        )

    except (OSError, ValueError, TypeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="LOG_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.log",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.log",
        )

    return result

def _parse_line(line, line_number):
    entry = {
        "line": line_number,
        "format": "unstructured",
        "timestamp": None,
        "level": None,
        "source": None,
        "hostname": None,
        "pid": None,
        "message": line,
        "raw": line,
    }

    access_match = ACCESS_LOG.match(line)

    if access_match:
        data = access_match.groupdict()

        return {
            "line": line_number,
            "format": "access_log",
            "timestamp": data["timestamp"],
            "level": None,
            "source": data["client"],
            "hostname": None,
            "pid": None,
            "message": data["request"],
            "client": data["client"],
            "identity": data["identity"],
            "user": data["user"],
            "status": int(data["status"]),
            "size": (
                int(data["size"])
                if data["size"].isdigit()
                else None
            ),
            "referer": data["referer"],
            "user_agent": data["user_agent"],
            "raw": line,
        }

    syslog_match = SYSLOG.match(line)

    if syslog_match:
        data = syslog_match.groupdict()

        return {
            "line": line_number,
            "format": "syslog",
            "timestamp": data["timestamp"],
            "level": _syslog_level(data["priority"]),
            "source": data["hostname"],
            "hostname": data["hostname"],
            "pid": None,
            "priority": (
                int(data["priority"])
                if data["priority"]
                else None
            ),
            "message": data["message"],
            "raw": line,
        }

    app_match = APP_LOG.match(line)

    if app_match:
        data = app_match.groupdict()

        if any(data.values()):
            level = data["level"]

            return {
                "line": line_number,
                "format": "application",
                "timestamp": data["timestamp"],
                "level": _normalise_level(level),
                "source": data["source"],
                "hostname": None,
                "pid": (
                    int(data["pid"])
                    if data["pid"]
                    else None
                ),
                "message": data["message"],
                "raw": line,
            }

    return entry

def _normalise_level(level):
    if not level:
        return None

    level = level.upper()

    if level == "WARN":
        return "WARNING"

    return level if level in LEVELS else None

def _syslog_level(priority):
    if priority is None:
        return None

    severity = int(priority) % 8

    levels = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFO",
        7: "DEBUG",
    }

    return levels.get(severity)