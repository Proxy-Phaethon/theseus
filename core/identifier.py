
"""Input identifier for Theseus.

Recognises accepted input-type flags and validates their accompanying
input. It does not select or execute extractors.
"""

from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET

from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from core.packets import Packet, PacketStatus

def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())

def _safe_path(value: Any) -> Path | None:
    """Return a Path only when the input can safely be treated as a path."""
    if not isinstance(value, (str, Path)):
        return None

    try:
        return Path(value).expanduser()
    except (OSError, ValueError, TypeError):
        return None

def _file(value: Any) -> bool:
    path = _safe_path(value)
    if path is None:
        return False

    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False

def _directory(value: Any) -> bool:
    path = _safe_path(value)
    if path is None:
        return False

    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False

def _has_extension(*extensions: str) -> Callable[[Any], bool]:
    extensions = tuple(ext.lower() for ext in extensions)

    def validate(value: Any) -> bool:
        path = _safe_path(value)

        if path is None or not _file(path):
            return False

        return str(path).lower().endswith(extensions)

    return validate

def _nonempty(value: Any) -> bool:
    if isinstance(value, bytes):
        return bool(value)

    return (
        _text(value)
        or isinstance(value, (dict, list))
    )

def _url(value: Any) -> bool:
    if not _text(value):
        return False

    try:
        parsed = urlsplit(value.strip())

        if parsed.scheme.lower() not in {"http", "https", "ftp"}:
            return False

        if not parsed.hostname:
            return False

        parsed.port
        return True

    except ValueError:
        return False

def _domain(value: Any) -> bool:
    if not _text(value):
        return False

    try:
        hostname = value.strip().rstrip(".").lower()

        if any(char in hostname for char in (":", "/", "@", "?", "#")):
            return False

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
    if not _text(value):
        return False

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False

def _cidr(value: Any) -> bool:
    if not _text(value):
        return False

    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False

def _hostname(value: Any) -> bool:
    if not _text(value):
        return False

    hostname = value.strip().rstrip(".")

    if _ip(hostname):
        return True

    if not hostname or len(hostname) > 253:
        return False

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    labels = hostname.split(".")

    return all(
        re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
            label,
        )
        for label in labels
    )

def _port(value: Any) -> bool:
    if not _text(value):
        return False

    match = re.fullmatch(
        r"(\d+)(?:/(tcp|udp))?",
        value.strip(),
        re.IGNORECASE,
    )

    return bool(
        match and 0 <= int(match.group(1)) <= 65535
    )

def _mac(value: Any) -> bool:
    return bool(
        _text(value)
        and re.fullmatch(
            r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}",
            value.strip(),
        )
    )

def _asn(value: Any) -> bool:
    return bool(
        _text(value)
        and re.fullmatch(
            r"(?:AS)?\d+",
            value.strip(),
            re.IGNORECASE,
        )
        and 1 <= int(value.strip().removeprefix("AS").removeprefix("as")) <= 4294967295
    )

def _hash(value: Any) -> bool:
    return bool(
        _text(value)
        and re.fullmatch(
            r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|"
            r"[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|"
            r"[a-fA-F0-9]{96}|[a-fA-F0-9]{128})",
            value.strip(),
        )
    )

def _pdf(value: Any) -> bool:
    if isinstance(value, bytes):
        return value.startswith(b"%PDF-")

    return _has_extension(".pdf")(value)

def _image(value: Any) -> bool:
    return _has_extension(
        ".jpg", ".jpeg", ".png", ".gif",
        ".bmp", ".tiff", ".tif", ".webp",
        ".ico", ".jfif", ".avif",
    )(value)

def _office(value: Any) -> bool:
    return _has_extension(
        ".docx", ".xlsx", ".pptx",
    )(value)

def _archive(value: Any) -> bool:
    return _has_extension(
        ".zip", ".tar", ".tar.gz", ".tgz",
        ".tar.bz2", ".tbz", ".tbz2",
        ".tar.xz", ".txz", ".gz", ".bz2", ".xz",
    )(value)

def _audio(value: Any) -> bool:
    return _has_extension(
        ".mp3", ".wav", ".flac", ".aac", ".m4a",
        ".ogg", ".opus", ".wma", ".aiff", ".aif",
        ".ape", ".wv", ".mp4",
    )(value)

def _video(value: Any) -> bool:
    return _has_extension(
        ".mp4", ".m4v", ".mkv", ".mov", ".avi",
        ".wmv", ".flv", ".webm", ".mpeg", ".mpg",
        ".m4p", ".3gp", ".3g2", ".ts", ".mts",
        ".m2ts", ".vob", ".ogv", ".asf",
    )(value)

def _font(value: Any) -> bool:
    return _has_extension(
        ".ttf", ".otf", ".ttc", ".woff", ".woff2",
    )(value)

def _shortcut(value: Any) -> bool:
    return _has_extension(
        ".lnk", ".url", ".desktop",
    )(value)

def _pcap(value: Any) -> bool:
    return _has_extension(".pcap", ".pcapng")(value)

def _file_or_content(value: Any) -> bool:
    return _file(value) or _nonempty(value)

def _json(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if candidate.startswith(("{", "[")):
        try:
            json.loads(candidate)
            return True
        except json.JSONDecodeError:
            return False

    path = _safe_path(candidate)

    if path is None or not _file(path):
        return False

    if path.suffix.lower() != ".json":
        return False

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            json.load(file)
        return True
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

def _xml(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if candidate.startswith("<"):
        if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", candidate, re.I):
            return False

        try:
            ET.fromstring(candidate)
            return True
        except ET.ParseError:
            return False

    path = _safe_path(candidate)

    if path is None or not _file(path) or path.suffix.lower() != ".xml":
        return False

    try:
        content = path.read_text(encoding="utf-8-sig")

        if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", content, re.I):
            return False

        ET.fromstring(content)
        return True
    except (OSError, UnicodeDecodeError, ET.ParseError):
        return False

def _csv(value: Any) -> bool:
    import csv

    if not _text(value):
        return False

    candidate = value.strip()

    path = _safe_path(candidate)

    if path is not None and _file(path):
        return path.suffix.lower() == ".csv"

    try:
        dialect = csv.Sniffer().sniff(candidate[:8192])
        return dialect.delimiter in (",", ";", "\t", "|")
    except csv.Error:
        return False

def _sqlite(value: Any) -> bool:
    if not _has_extension(".db", ".sqlite", ".sqlite3")(value):
        return False

    try:
        with Path(value).open("rb") as file:
            return file.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False

def _config(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    if path is not None and _file(path):
        return path.suffix.lower() in (
            ".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml", ".json",
        )

    if candidate.startswith(("{", "[")):
        return _json(candidate)

    if re.search(r"(?m)^\s*\[[^\]]+\]\s*$", candidate):
        return True

    if re.search(r"(?m)^\s*[A-Za-z_][\w.-]*\s*:", candidate):
        return True

    if re.search(r"(?m)^\s*[A-Za-z_][\w.-]*\s*=", candidate):
        return True

    return False

def _env(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    if path is not None and _file(path):
        return path.name.lower() == ".env" or path.name.lower().startswith(".env.")

    for line in candidate.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[7:].lstrip()

        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            return True

    return False

def _email(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if "\n" in candidate or "\r" in candidate:
        return any(
            re.match(
                r"^(From|Received|Message-ID|Subject|Date):",
                line,
                re.IGNORECASE,
            )
            for line in candidate.splitlines()
        )

    return _has_extension(".eml", ".mbox")(candidate)

def _contact(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if "BEGIN:VCARD" in candidate.upper():
        return "END:VCARD" in candidate.upper()

    if re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        candidate,
    ):
        return True

    if re.fullmatch(r"\+?[\d\s().-]+", candidate):
        digits = re.sub(r"\D", "", candidate)
        return 7 <= len(digits) <= 15

    return _has_extension(".vcf")(candidate)

def _calendar(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if "BEGIN:VCALENDAR" in candidate.upper():
        return "END:VCALENDAR" in candidate.upper()

    return _has_extension(".ics")(candidate)

def _git_repository(value: Any) -> bool:
    path = _safe_path(value)

    if path is None or not _directory(path):
        return False

    try:
        return (
            (path / ".git").exists()
            or (path / "HEAD").is_file()
        )
    except OSError:
        return False

def _git_commit(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if "::" in candidate:
        repository, commit = candidate.rsplit("::", 1)
        path = _safe_path(repository)

        return bool(
            path
            and _git_repository(path)
            and re.fullmatch(r"[0-9a-fA-F]{4,64}", commit.strip())
        )

    return bool(
        re.fullmatch(r"[0-9a-fA-F]{4,64}", candidate)
    )

def _package(value: Any) -> bool:
    if not _text(value):
        return False

    filename = Path(value).name.lower()

    supported = {
        "pyproject.toml", "setup.py", "setup.cfg", "pkg-info",
        "package.json", "package-lock.json",
        "cargo.toml", "cargo.lock",
        "composer.json", "composer.lock",
        "pom.xml", "gemfile.lock",
    }

    return (
        filename in supported or filename.endswith(".gemspec")
    ) and _file(value)

def _registry(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    if path is not None and _file(path):
        try:
            with path.open("rb") as file:
                header = file.read(16)

            return (
                header.startswith(b"regf")
                or path.suffix.lower() == ".reg"
            )
        except OSError:
            return False

    return bool(
        re.search(
            r"(?im)^\s*(?:Windows Registry Editor Version 5\.00|REGEDIT4)\s*$",
            candidate,
        )
    )

def _log(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    if path is not None and _file(path):
        return path.suffix.lower() in (".log", ".logs", ".syslog")

    return (
        "\n" in candidate
        and bool(
            re.search(
                r"(?im)\b(ERROR|WARNING|INFO|DEBUG|CRITICAL|NOTICE|FATAL)\b"
                r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b",
                candidate,
            )
        )
    )

def _browser(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    artefacts = {
        "history",
        "places.sqlite",
        "cookies",
        "cookies.sqlite",
        "login data",
        "web data",
        "bookmarks",
    }

    if path is not None and _directory(path):
        try:
            return any(
                (path / name).is_file()
                for name in artefacts
            )
        except OSError:
            return False

    if path is not None and _file(path):
        return path.name.lower() in artefacts

    return False

def _har(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()

    if candidate.startswith("{"):
        try:
            document = json.loads(candidate)
            return (
                isinstance(document, dict)
                and isinstance(document.get("log"), dict)
                and isinstance(document["log"].get("entries", []), list)
            )
        except json.JSONDecodeError:
            return False

    path = _safe_path(candidate)

    if path is None or not _file(path) or path.suffix.lower() != ".har":
        return False

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            document = json.load(file)

        return (
            isinstance(document, dict)
            and isinstance(document.get("log"), dict)
            and isinstance(document["log"].get("entries", []), list)
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

def _sbom(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    if path is None or not _file(path):
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

            return (
                b"<bom" in content
                and b"cyclonedx.org/schema" in content
            )

    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    return False

def _container(value: Any) -> bool:
    if not _text(value):
        return False

    candidate = value.strip()
    path = _safe_path(candidate)

    if path is not None and _directory(path):
        return (
            (path / "oci-layout").is_file()
            and (path / "index.json").is_file()
        )

    if path is None or not _file(path):
        return False

    filename = path.name.lower()

    if filename == "dockerfile" or filename.startswith("dockerfile."):
        return True

    if filename in {
        "compose.yaml", "compose.yml",
        "docker-compose.yaml", "docker-compose.yml",
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
                    or ("apiVersion" in document and "kind" in document)
                    or ("manifests" in document and "schemaVersion" in document)
                )
            )

        if filename.endswith((".yaml", ".yml")):
            with path.open("r", encoding="utf-8-sig") as file:
                content = file.read(8192)

            return (
                "services:" in content
                or ("apiVersion:" in content and "kind:" in content)
            )

    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    return False

VALIDATORS: dict[str, Callable[[Any], bool]] = {
    "url": _url,
    "domain": _domain,
    "hostname": _hostname,
    "ip": _ip,
    "cidr": _cidr,
    "port": _port,
    "mac-address": _mac,
    "asn": _asn,

    "file": _file,
    "directory": _directory,
    "hash": _hash,

    "pdf": _pdf,
    "office-document": _office,
    "image": _image,
    "audio": _audio,
    "video": _video,
    "archive": _archive,
    "binary-file": lambda value: _file(value),
    "font": _font,
    "shortcut": _shortcut,

    "network-capture": _pcap,
    "http-message": lambda value: isinstance(value, dict),
    "html-document": _nonempty,
    "javascript-source": _nonempty,
    "css-source": _nonempty,
    "tls-host": _hostname,
    "certificate": _nonempty,

    "email": _email,
    "contact": _contact,
    "calendar": _calendar,
    "browser-profile": _browser,
    "http-archive": _har,
    "log": _log,

    "git-repository": _git_repository,
    "git-commit": _git_commit,

    "package-manifest": _package,
    "sbom-document": _sbom,
    "container-artefact": _container,

    "json-document": _json,
    "xml-document": _xml,
    "csv-document": _csv,
    "sqlite-database": _sqlite,
    "config-file": _config,
    "environment-file": _env,
    "registry-artefact": _registry,
}

class Identifier:
    """Recognises accepted input flags and validates their input."""

    def identify(self, packet: Packet) -> Packet:
        if not isinstance(packet, Packet):
            raise TypeError("Identifier requires a Packet.")

        flag = packet.metadata.get("flag")

        if not isinstance(flag, str) or not flag.strip():
            return self._failure(
                packet,
                "MISSING_FLAG",
                "No input flag was provided.",
            )

        flag = flag.strip().lower()

        if not flag.startswith("--"):
            return self._failure(
                packet,
                "INVALID_FLAG_FORMAT",
                "Input flags must begin with '--'.",
            )

        if flag not in VALIDATORS:
            return self._failure(
                packet,
                "UNKNOWN_FLAG",
                f"Unsupported input flag: {flag}",
            )

        validator = VALIDATORS[flag[2:]]

        try:
            valid = validator(packet.input)
        except Exception:
            valid = False

        if not valid:
            return self._failure(
                packet,
                "INVALID_INPUT",
                f"Input does not match the expected format for {flag}.",
            )

        report = packet.child(
            stage="identification",
            artefact_type=flag[2:],
            input=packet.input,
            status=PacketStatus.SUCCESS,
        )

        report.metadata = {
            "flag": flag,
            "identified": True,
        }

        report.data = {
            "recognised_flag": flag,
            "artefact_type": flag[2:],
        }

        return report

    @staticmethod
    def _failure(
        packet: Packet,
        code: str,
        message: str,
    ) -> Packet:
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