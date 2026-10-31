"""Input identifier for Theseus.

Validates input flags and checks whether their accompanying
content matches the expected artefact type.
"""

from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET

from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from email.utils import parseaddr

from core.packets import Packet, PacketStatus

def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())

def _url(value: Any) -> bool:
    if not _text(value):
        return False

    try:
        parsed = urlsplit(value.strip())

        if parsed.scheme.lower() not in {"http", "https", "ftp"}:
            return False

        if not parsed.hostname:
            return False

        parsed.port  # Accessing this validates the port, if present.

        return True

    except ValueError:
        return False

def _domain(value: Any) -> bool:
    if not _text(value):
        return False

    try:
        hostname = value.strip().rstrip(".").lower()

        if "://" in hostname or "/" in hostname or "@" in hostname:
            return False

        import ipaddress

        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            pass

        hostname = hostname.encode("idna").decode("ascii")

        labels = hostname.split(".")

        if len(labels) < 2:
            return False

        return all(
            re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                label,
            )
            for label in labels
        )

    except (ValueError, UnicodeError):
        return False

def _ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except (ValueError, AttributeError):
        return False

def _cidr(value: Any) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except (ValueError, AttributeError):
        return False

def _hostname(value: Any) -> bool:
    return _domain(value) or _ip(value)

def _port(value: Any) -> bool:
    try:
        port = int(value)
        return 0 <= port <= 65535
    except (ValueError, TypeError):
        return False

def _hash(value: Any) -> bool:
    if not _text(value):
        return False

    return bool(re.fullmatch(
        r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|"
        r"[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|"
        r"[a-fA-F0-9]{96}|[a-fA-F0-9]{128})",
        value.strip(),
    ))

def _email(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    # Raw email source
    if "\n" in candidate or "\r" in candidate:
        return (
            "From:" in candidate
            or "Received:" in candidate
            or "Message-ID:" in candidate
        )

    # Email file
    return _has_extension(".eml", ".mbox")(candidate)

def _file_input(value: Any) -> bool:
    if isinstance(value, bytes):
        return bool(value)

    if isinstance(value, Path):
        return value.is_file()

    if isinstance(value, str):
        try:
            return Path(value).is_file()
        except (OSError, ValueError):
            return False

    return False

def _directory(value: Any) -> bool:
    if not isinstance(value, (str, Path)):
        return False

    try:
        return Path(value).is_dir()
    except (OSError, ValueError):
        return False

def _structured(value: Any) -> bool:
    return isinstance(value, (dict, list)) or _text(value)

def _json(value: Any) -> bool:
    if isinstance(value, (dict, list)):
        return True

    if not _text(value):
        return False

    try:
        json.loads(value)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def _xml(value: Any) -> bool:
    if not _text(value):
        return False

    try:
        ET.fromstring(value)
        return True
    except ET.ParseError:
        return False

def _pdf(value: Any) -> bool:
    if isinstance(value, bytes):
        return value.startswith(b"%PDF-")

    if isinstance(value, (str, Path)):
        return str(value).lower().endswith(".pdf") and _file_input(value)

    return False

def _image(value: Any) -> bool:
    signatures = (
        b"\xff\xd8\xff",                 # JPEG
        b"\x89PNG\r\n\x1a\n",           # PNG
        b"GIF87a", b"GIF89a",           # GIF
        b"BM",                           # BMP
        b"RIFF",                         # WebP (additional check below)
    )

    if isinstance(value, bytes):
        return (
            any(value.startswith(sig) for sig in signatures[:-1])
            or (
                value.startswith(b"RIFF")
                and value[8:12] == b"WEBP"
            )
        )

    if isinstance(value, (str, Path)):
        return (
            str(value).lower().endswith(
                (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff")
            )
            and _file_input(value)
        )

    return False

def _has_extension(*extensions: str) -> Callable[[Any], bool]:
    def validate(value: Any) -> bool:
        return (
            isinstance(value, (str, Path))
            and str(value).lower().endswith(extensions)
            and _file_input(value)
        )
    return validate

def _nonempty(value: Any) -> bool:
    if isinstance(value, bytes):
        return bool(value)

    return _text(value) or isinstance(value, (dict, list))

# Flag-to-validator mapping
VALIDATORS: dict[str, Callable[[Any], bool]] = {
    "url": _url,
    "domain": _domain,
    "dns": _domain,
    "ip": _ip,
    "cidr": _cidr,
    "hostname": _hostname,
    "redirect": _url,
    "http": _structured,
    "webpage": lambda value: _url(value) or _text(value),
    "javascript": _nonempty,
    "css": _nonempty,
    "asn": lambda value: bool(re.fullmatch(r"(?:AS)?\d+", str(value).strip(), re.I)),
    "mac": lambda value: bool(re.fullmatch(
        r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", str(value).strip()
    )),
    "bssid": lambda value: bool(re.fullmatch(
        r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", str(value).strip()
    )),
    "port": _port,
    "certificate": _nonempty,
    "tls": _url,
    "pcap": _has_extension(".pcap", ".pcapng"),
    "flow": _structured,
    "file": _file_input,
    "hash": _hash,
    "pdf": _pdf,
    "office": _has_extension(
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"
    ),
    "image": _has_extension(
        ".jpg", ".jpeg", ".png", ".gif",
        ".bmp", ".tiff", ".tif", ".webp",
        ".ico", ".jfif", ".avif",
    ),
    "audio": _has_extension(
        ".mp3", ".wav", ".flac", ".aac", ".m4a",
        ".ogg", ".opus", ".wma", ".aiff", ".aif",
        ".ape", ".wv", ".mp4",
    ),
    "video": _has_extension(
        ".mp4", ".m4v", ".mkv", ".mov", ".avi",
        ".wmv", ".flv", ".webm", ".mpeg", ".mpg",
        ".m4p", ".3gp", ".3g2", ".ts", ".mts",
        ".m2ts", ".vob", ".ogv", ".asf",
    ),
    "archive": _has_extension(
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz",
        ".tbz2",
        ".tar.xz",
        ".txz",
        ".gz",
        ".bz2",
        ".xz",
    ),
    "binary": lambda value: isinstance(value, bytes) or _file_input(value),
    "font": _has_extension(
        ".ttf", ".otf", ".ttc", ".woff", ".woff2",
    ),
    "shortcut": _has_extension(
        ".lnk",
        ".url",
        ".desktop",
    ),
    "directory": _directory,
    "email": _email,
    "email_headers": _structured,
    "message_id": lambda value: (
        _text(value) and bool(re.fullmatch(r"<[^<>\s]+@[^<>\s]+>", value.strip()))
    ),
    "contact": _structured,
    "calendar": _structured,
    "vcf": _has_extension(".vcf"),
    "ics": _has_extension(".ics"),
    "git_repository": _nonempty,
    "git_commit": lambda value: (
        _text(value) and bool(re.fullmatch(r"[a-fA-F0-9]{7,64}", value.strip()))
    ),
    "package": _nonempty,
    "sbom": _structured,
    "container": _nonempty,
    "api_spec": _structured,
    "cve": lambda value: (
        _text(value) and bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", value.strip(), re.I))
    ),
    "json": _json,
    "xml": _xml,
    "csv": _has_extension(".csv"),
    "sqlite": _has_extension(".db", ".sqlite", ".sqlite3"),
    "config": _nonempty,
    "env": _nonempty,
    "registry": _nonempty,
    "log": _nonempty,
    "browser": _structured,
    "har": _json,
}

class Identifier:
    """Validates input flags and their accompanying content."""

    def identify(self, packet: Packet) -> Packet:
        """Validate an input Packet and produce an identification report."""

        if not isinstance(packet, Packet):
            raise TypeError("Identifier requires a Packet.")

        flag = packet.metadata.get("flag")

        if not isinstance(flag, str) or not flag.strip():
            return self._failure(packet, "missing_flag", "No input flag was provided.")

        flag = flag.strip().lower()

        if flag.startswith("--"):
            flag = flag[2:]

        validator = VALIDATORS.get(flag)

        if validator is None:
            return self._failure(
                packet,
                "unknown_flag",
                f"Unsupported input flag: --{flag}",
            )

        if not validator(packet.input):
            return self._failure(
                packet,
                "invalid_input",
                f"Input does not match the expected format for --{flag}.",
            )

        report = packet.child(
            stage="identification",
            artefact_type=flag,
            input=packet.input,
            status=PacketStatus.SUCCESS,
        )

        report.metadata = {
            "flag": f"--{flag}",
            "identified": True,
        }

        report.data = {
            "recognised_flag": f"--{flag}",
            "artefact_type": flag,
        }

        return report

    @staticmethod
    def _failure(packet: Packet, code: str, message: str) -> Packet:
        """Create a failed identification report."""

        report = packet.child(
            stage="identification",
            artefact_type="unknown",
            input=packet.input,
            status=PacketStatus.NOT_SUPPORTED,
        )

        report.metadata = {
            "identified": False,
        }

        report.add_error(
            code=code,
            message=message,
            component="core.identifier",
        )

        return report