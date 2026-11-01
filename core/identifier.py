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
from extractors import csv
from extractors.config import _detect_format
from extractors.contact import EMAIL_PATTERN, PHONE_PATTERN

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

def _email_headers(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    # Raw email/header source.
    if "\n" in candidate or "\r" in candidate:
        header_names = (
            "From:",
            "To:",
            "Subject:",
            "Date:",
            "Received:",
            "Message-ID:",
            "Return-Path:",
        )

        return any(
            line.lower().startswith(tuple(name.lower() for name in header_names))
            for line in candidate.splitlines()
        )

    # File-based input.
    return _has_extension(".eml")(candidate)

def _message_id(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    # Raw email source.
    if "\n" in candidate or "\r" in candidate:
        return any(
            line.lower().startswith("message-id:")
            for line in candidate.splitlines()
        )

    # Direct Message-ID value.
    if candidate.startswith("<") and candidate.endswith(">"):
        return bool(
            re.fullmatch(
                r"<[^<>\s@]+@[^<>\s@]+>",
                candidate,
            )
        )

    # Email source file.
    return _has_extension(".eml")(candidate)

def _contact(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    if "BEGIN:VCARD" in candidate.upper():
        return True

    if "\n" in candidate or "\r" in candidate:
        return False

    if EMAIL_PATTERN.fullmatch(candidate):
        return True

    if PHONE_PATTERN.fullmatch(candidate):
        digits = re.sub(r"\D", "", candidate)
        return 7 <= len(digits) <= 15

    return _has_extension(".vcf")(candidate)

def _calendar(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    if "\n" in candidate or "\r" in candidate:
        return (
            "BEGIN:VCALENDAR" in candidate.upper()
            and "END:VCALENDAR" in candidate.upper()
        )

    return _has_extension(".ics")(candidate)

def _vcf(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    if "\n" in candidate or "\r" in candidate:
        return (
            "BEGIN:VCARD" in candidate.upper()
            and "END:VCARD" in candidate.upper()
        )

    return _has_extension(".vcf")(candidate)

def _ics(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    return _has_extension(".ics")(candidate)

def _git_repository(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value.strip())

    try:
        return (
            path.is_dir()
            and (
                (path / ".git").exists()
                or (path / "HEAD").exists()
            )
        )
    except OSError:
        return False

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

def _json(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()
    path = Path(candidate)

    if path.is_file():
        return path.suffix.lower() == ".json"

    try:
        json.loads(candidate)
        return True
    except (json.JSONDecodeError, ValueError):
        return False

def _sbom(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value).expanduser()

    if not path.is_file():
        return False

    filename = path.name.lower()

    try:
        if filename.endswith(".spdx"):
            with path.open("r", encoding="utf-8-sig") as file:
                return "SPDXVersion:" in file.read(4096)

        if filename.endswith((".yaml", ".yml")):
            with path.open("r", encoding="utf-8-sig") as file:
                content = file.read(4096)
                return "spdxVersion:" in content or "SPDXVersion:" in content

        if filename.endswith(".json"):
            with path.open("r", encoding="utf-8-sig") as file:
                document = json.load(file)

            return (
                isinstance(document, dict)
                and (
                    document.get("bomFormat") == "CycloneDX"
                    or bool(document.get("spdxVersion"))
                )
            )

        if filename.endswith(".xml"):
            with path.open("rb") as file:
                content = file.read(4096)

            return b"<bom" in content and b"cyclonedx.org/schema" in content

    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    return False

def _xml(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()
    path = Path(candidate)

    if path.is_file():
        return path.suffix.lower() == ".xml"

    if not candidate.startswith("<"):
        return False

    if re.search(
        r"<!\s*(DOCTYPE|ENTITY)\b",
        candidate,
        flags=re.IGNORECASE,
    ):
        return False

    try:
        ET.fromstring(candidate)
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

def _git_commit(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()

    if "::" in candidate:
        repository_path, commit_reference = candidate.rsplit("::", 1)

        if not repository_path.strip() or not commit_reference.strip():
            return False

        path = Path(repository_path.strip())

        try:
            return (
                path.is_dir()
                and (
                    (path / ".git").exists()
                    or (path / "HEAD").exists()
                )
                and bool(re.fullmatch(
                    r"[0-9a-fA-F]{4,64}",
                    commit_reference.strip(),
                ))
            )
        except OSError:
            return False

    return bool(
        re.fullmatch(r"[0-9a-fA-F]{4,64}", candidate)
    )

def _nonempty(value: Any) -> bool:
    if isinstance(value, bytes):
        return bool(value)

    return _text(value) or isinstance(value, (dict, list))

def _package(value):
    if not isinstance(value, str) or not value.strip():
        return False

    filename = Path(value).name.lower()

    supported = {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pkg-info",
        "package.json",
        "package-lock.json",
        "cargo.toml",
        "cargo.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
        "gemfile.lock",
    }

    return filename in supported or filename.endswith(".gemspec")

def _container(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value).expanduser()

    if path.is_dir():
        return (
            (path / "oci-layout").is_file()
            and (path / "index.json").is_file()
        )

    if not path.is_file():
        return False

    filename = path.name.lower()

    if filename == "dockerfile" or filename.startswith("dockerfile."):
        return True

    if filename in {
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    }:
        return True

    if filename.endswith((".tar", ".tar.gz", ".tgz")):
        return True

    try:
        if filename.endswith(".json"):
            with path.open("r", encoding="utf-8-sig") as file:
                document = json.load(file)

            return (
                isinstance(document, dict)
                and (
                    "services" in document
                    or (
                        "apiVersion" in document
                        and "kind" in document
                    )
                    or (
                        "manifests" in document
                        and "schemaVersion" in document
                    )
                )
            )

        if filename.endswith((".yaml", ".yml")):
            with path.open("r", encoding="utf-8-sig") as file:
                content = file.read(8192)

            return (
                "services:" in content
                or (
                    "apiVersion:" in content
                    and "kind:" in content
                )
            )

    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    return False

def _csv(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()
    path = Path(candidate)

    if path.is_file():
        return path.suffix.lower() == ".csv"

    try:
        sample = candidate[:8192]
        dialect = csv.Sniffer().sniff(sample)

        return dialect.delimiter in (",", ";", "\t", "|")

    except csv.Error:
        return False

def _sqlite(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value.strip())

    if not path.is_file():
        return False

    if path.suffix.lower() not in (".db", ".sqlite", ".sqlite3"):
        return False

    try:
        with path.open("rb") as file:
            return file.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False

def _config(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()
    path = Path(candidate)

    if path.is_file():
        return path.suffix.lower() in (
            ".ini",
            ".cfg",
            ".conf",
            ".toml",
            ".yaml",
            ".yml",
            ".json",
        )

    try:
        _detect_format(candidate)
        return True
    except (ValueError, ImportError):
        return False

def _env(value):
    if not isinstance(value, str) or not value.strip():
        return False

    candidate = value.strip()
    path = Path(candidate)

    if path.is_file():
        return path.name.lower() == ".env" or path.name.lower().startswith(".env.")

    for line in candidate.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[7:].lstrip()

        if re.match(
            r"^[A-Za-z_][A-Za-z0-9_]*\s*=",
            line,
        ):
            return True

    return False


def _looks_like_reg(raw):
    return bool(
        re.search(
            r"(?im)^\s*Windows Registry Editor Version 5\.00\s*$"
            r"|^\s*REGEDIT4\s*$",
            raw,
        )
    )

def _registry(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value.strip())

    if path.is_file():
        try:
            with path.open("rb") as file:
                header = file.read(16)

            return (
                header == b"regf"
                or path.suffix.lower() == ".reg"
            )
        except OSError:
            return False

    return _looks_like_reg(value.strip())

def _log(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value.strip())

    if path.is_file():
        return path.suffix.lower() in (
            ".log",
            ".logs",
            ".syslog",
        )

    candidate = value.strip()

    return "\n" in candidate and any(
        marker in candidate
        for marker in (
            "ERROR",
            "WARNING",
            "INFO",
            "DEBUG",
            "CRITICAL",
            "Jan ",
            "Feb ",
            "Mar ",
            "Apr ",
            "May ",
            "Jun ",
            "Jul ",
            "Aug ",
            "Sep ",
            "Oct ",
            "Nov ",
            "Dec ",
        )
    )

def _browser(value):
    if not isinstance(value, str) or not value.strip():
        return False

    path = Path(value.strip())

    if path.is_dir():
        return any(
            (path / name).is_file()
            for name in (
                "History",
                "places.sqlite",
                "Cookies",
                "cookies.sqlite",
                "Login Data",
                "Web Data",
                "Bookmarks",
            )
        )

    if path.is_file():
        return path.name.lower() in {
            "history",
            "places.sqlite",
            "cookies",
            "cookies.sqlite",
            "login data",
            "web data",
            "bookmarks",
        }

    return False

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
    "email-headers": _email_headers,
    "message-id": _message_id,
        "contact": _structured,
        "calendar": _structured,
        "vcf": _has_extension(".vcf"),
        "ics": _has_extension(".ics"),
        "git_repository": _nonempty,
        "git_commit": lambda value: (
            _text(value) and bool(re.fullmatch(r"[a-fA-F0-9]{7,64}", value.strip()))
        ),
    "contact": _contact,
    "package": _package,
    "sbom": _structured,
    "container": _nonempty,
    "api_spec": _structured,
    "cve": lambda value: (
        _text(value) and bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", value.strip(), re.I))
    ),
    "calendar": _calendar,
    "vcf": _vcf,
    "ics": _ics,
    "git-repository": _git_repository,
    "git-commit": _git_commit,
    "sbom": _sbom,
    "container": _container,
    "json": _json,
    "xml": _xml,
    "csv": _csv,
    "sqlite": _sqlite,
    "config": _config,
    "env": _env,
    "registry": _registry,
    "log": _log,
    "browser": _browser,
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