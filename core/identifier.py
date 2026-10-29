"""Input classification and artefact recognition for Theseus.

The identifier is deliberately local and deterministic. It does not perform
network requests, infer identity links, or select extractors.

Public API:
    identify(value) -> Packet
    Identifier().identify(value) -> Packet

The returned Packet is the universal Theseus envelope. A successfully
classified input has stage="identification" and data containing input_type,
confidence, and every recognised artefact. Unsupported or ambiguous input
returns PacketStatus.NOT_SUPPORTED with a structured error.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    from .packets import Packet, PacketStatus
except ImportError:  # Supports running this module directly from core/.
    from packets import Packet, PacketStatus

# Input types accepted at the boundary. These are intentionally separate from
# artefact types found inside an input.
INPUT_TYPES = {
    "url", "domain", "hostname", "subdomain", "ip_address", "ip_range",
    "asn", "mac_address", "ssid", "bssid", "bluetooth_address", "host_port",
    "certificate_fingerprint", "certificate_serial", "ssh_fingerprint",
    "public_key_fingerprint", "ct_hostname", "email_address", "phone_number",
    "username", "social_profile_url", "person_name", "gravatar_hash",
    "git_author_identity", "repository_slug", "account_id", "device_identifier",
    "company_name", "company_registration_number", "stock_ticker", "lei",
    "patent_number", "trademark", "court_case_number", "procurement_id",
    "licence_number", "academic_identifier", "press_release_url", "job_ad_url",
    "advertiser_name", "git_repository_url", "commit_hash", "package_reference",
    "container_image", "cve_id", "api_spec_url", "cloud_resource_identifier",
    "jwt", "api_key_or_token", "oauth_oidc", "password_hash", "recovery_link",
    "private_key", "kerberos_ticket", "file_hash", "perceptual_hash",
    "message_id", "email_file", "calendar_file", "contact_file", "pdf_file",
    "office_document", "media_file", "executable_file", "font_file", "shortcut",
    "archive", "config_file", "structured_data_file", "geospatial_file",
    "subtitle_file", "log_file", "directory_tree", "forensic_image",
    "triage_collection", "browser_profile", "mobile_backup", "packet_capture",
    "flow_records", "account_export", "password_manager_export", "web_archive",
    "cloud_audit_export", "network_config_backup", "sbom_or_lockfile_bundle",
    "gps_coordinates", "street_address_or_place", "map_url", "place_id",
    "keyword_phrase", "free_text_blob", "timestamp_or_time_range", "case_scope",
}

# Extensions are a first-pass signal, not proof of file contents. If a real
# local file is supplied, its magic bytes are checked before its extension.
EXTENSION_TYPES: dict[str, str] = {}
for extensions, kind in [
    ((".eml", ".msg", ".mbox"), "email_file"),
    ((".ics",), "calendar_file"),
    ((".vcf",), "contact_file"),
    ((".pdf",), "pdf_file"),
    ((".doc", ".docx", ".odt", ".rtf", ".xls", ".xlsx", ".ods",
      ".ppt", ".pptx", ".odp"), "office_document"),
    ((".png", ".jpg", ".jpeg", ".gif", ".webp", ".tif", ".tiff", ".bmp",
      ".heic", ".svg", ".mp3", ".wav", ".flac", ".mp4", ".mov", ".mkv",
      ".avi", ".webm", ".m4a", ".ogg"), "media_file"),
    ((".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".app", ".dmg",
      ".wasm", ".class", ".jar"), "executable_file"),
    ((".ttf", ".otf", ".woff", ".woff2"), "font_file"),
    ((".lnk", ".alias"), "shortcut"),
    ((".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
      ".zst"), "archive"),
    ((".env", ".ini", ".conf", ".cfg", ".toml", ".properties"), "config_file"),
    ((".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml", ".yaml",
      ".yml", ".sql", ".sqlite", ".sqlite3", ".db"), "structured_data_file"),
    ((".gpx", ".kml", ".kmz", ".geojson", ".shp", ".shx", ".dbf", ".prj"),
     "geospatial_file"),
    ((".srt", ".vtt", ".ass", ".ssa", ".sub"), "subtitle_file"),
    ((".log", ".evtx", ".etl", ".syslog"), "log_file"),
    ((".img", ".dd", ".raw", ".e01", ".aff", ".aff4", ".vmdk", ".vhd",
      ".vhdx"), "forensic_image"),
    ((".pcap", ".pcapng"), "packet_capture"),
    ((".warc", ".warc.gz", ".har"), "web_archive"),
    ((".mobileconfig",), "config_file"),
    ((".plist", ".reg", ".evtx"), "triage_collection"),
    ((".lock", ".lockb", ".sum", ".spdx", ".cdx.json"), "sbom_or_lockfile_bundle"),
]:
    for extension in extensions:
        EXTENSION_TYPES[extension] = kind

# Longest/specific patterns are tested before broad patterns.
PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("cve_id", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I), 0.99),
    ("lei", re.compile(r"\b[A-Z0-9]{18}\d{2}\b", re.I), 0.75),
    ("stock_ticker", re.compile(r"^\$?[A-Z]{1,5}$"), 0.55),
    ("asn", re.compile(r"^(?:AS|ASN)\s*\d{1,10}$", re.I), 0.99),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), 0.99),
    ("email_address", re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I), 0.99),
    ("url", re.compile(r"\bhttps?://[^\s<>\"']+", re.I), 0.99),
    ("git_repository_url", re.compile(r"\b(?:git@[\w.-]+:[\w./-]+|https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)/[\w.-]+/[\w.-]+(?:\.git)?)\b", re.I), 0.98),
    ("cve_id", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I), 0.99),
    ("commit_hash", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"), 0.80),
    ("file_hash", re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Fa-f0-9])"), 0.75),
    ("gravatar_hash", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"), 0.60),
    ("certificate_fingerprint", re.compile(r"\b(?:SHA-?256|SHA-?1|MD5)\s*[:=]\s*(?:[A-Fa-f0-9]{2}[:-]?){16,32}\b", re.I), 0.98),
    ("ssh_fingerprint", re.compile(r"\bSHA256:[A-Za-z0-9+/]{20,}={0,2}\b"), 0.99),
    ("mac_address", re.compile(r"(?<![\w])(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}(?![\w])", re.I), 0.99),
    ("bluetooth_address", re.compile(r"(?<![\w])(?:[0-9A-F]{2}:){5}[0-9A-F]{2}(?![\w])", re.I), 0.94),
    ("ip_range", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|(?<![\w:])[0-9a-f:]+/[0-9]{1,3}\b", re.I), 0.95),
    ("ip_address", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I), 0.70),
    ("host_port", re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9a-f:]+\]):\d{1,5}\b", re.I), 0.92),
    ("phone_number", re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)"), 0.60),
    ("message_id", re.compile(r"(?im)^\s*Message-ID\s*:\s*<?[^>\s]+@[^>\s]+>?\s*$"), 0.99),
    ("doi", re.compile(r"\b10\.\d{4,9}/[-._;()/:A-Z0-9]+\b", re.I), 0.98),
    ("orcid", re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b", re.I), 0.99),
    ("patent_number", re.compile(r"\b(?:US|EP|WO|GB|IN)\s?(?:\d{6,}|[A-Z]\d{6,})\b", re.I), 0.70),
    ("commit_hash", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{7,40}(?![A-Fa-f0-9])"), 0.55),
    ("cloud_resource_identifier", re.compile(r"\barn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:[^\s,;]+", re.I), 0.99),
    ("package_reference", re.compile(r"\bpkg:[a-z][a-z0-9.+-]*/[^\s?#]+", re.I), 0.99),
    ("container_image", re.compile(r"\b[\w.-]+(?::\d+)?/[\w./-]+:[\w.-]+\b"), 0.72),
    ("password_hash", re.compile(r"\$(?:2[aby]|argon2(?:id|i|d)|scrypt|pbkdf2)[^$\s]*(?:\$[^$\s]+){1,}"), 0.95),
    ("recovery_link", re.compile(r"https?://[^\s]*(?:reset|recover|verify|password|token)[^\s]*", re.I), 0.65),
    ("certificate_serial", re.compile(r"\b(?:serial(?: number)?|cert serial)\s*[:=]\s*[A-F0-9:-]{6,}\b", re.I), 0.90),
    ("place_id", re.compile(r"\b(?:place[_ -]?id)\s*[:=]\s*[\w-]{4,}\b", re.I), 0.95),
    ("gps_coordinates", re.compile(r"(?<![\d.])-?(?:[0-8]?\d(?:\.\d+)?|90(?:\.0+)?)[,\s]+-?(?:1[0-7]\d(?:\.\d+)?|180(?:\.0+)?|(?:\d?\d)(?:\.\d+)?)(?![\d.])"), 0.55),
    ("timestamp_or_time_range", re.compile(r"\b(?:\d{4}-\d{2}-\d{2}(?:[T ][0-2]\d:[0-5]\d(?::[0-6]\d(?:\.\d+)?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?|\d{1,2}:\d{2}(?:\s?(?:AM|PM))?)\b", re.I), 0.70),
    ("domain", re.compile(r"(?<![@\w-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![\w-])", re.I), 0.78),
    ("username", re.compile(r"(?<![\w@])@[A-Za-z0-9_.-]{2,32}\b"), 0.82),
    ("api_key_or_token", re.compile(r"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*[A-Za-z0-9_./+=-]{12,}", re.I), 0.97),
    ("keyword_phrase", re.compile(r"^\s*[\w][\w .,'\"()&/-]{2,119}\s*$"), 0.52),
]

def _safe_input(value: Any) -> Any:
    """Return a Packet-serialisable representation of input."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"kind": "bytes", "length": len(value), "hex_prefix": value[:24].hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _safe_input(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_input(v) for v in value]
    return repr(value)

def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False

def _valid_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

def _looks_like_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return parts.scheme.lower() in {"http", "https", "ftp", "file"} and bool(parts.netloc or parts.scheme == "file")
    except ValueError:
        return False

def _domain_type(value: str) -> str | None:
    candidate = value.rstrip(".").lower()
    if not candidate or " " in candidate or len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        return None
    if not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        return None
    return "subdomain" if len(labels) > 2 else "domain"

def _magic_type(data: bytes) -> str | None:
    signatures: list[tuple[bytes, str]] = [
        (b"%PDF-", "pdf_file"),
        (b"PK\x03\x04", "archive"),  # ZIP-based Office formats need deeper inspection.
        (b"Rar!\x1a\x07", "archive"),
        (b"7z\xbc\xaf\x27\x1c", "archive"),
        (b"\x1f\x8b", "archive"),
        (b"SQLite format 3\x00", "structured_data_file"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office_document"),
        (b"\x7fELF", "executable_file"),
        (b"MZ", "executable_file"),
        (b"\xca\xfe\xba\xbe", "executable_file"),
        (b"\x89PNG\r\n\x1a\n", "media_file"),
        (b"\xff\xd8\xff", "media_file"),
        (b"GIF87a", "media_file"),
        (b"GIF89a", "media_file"),
        (b"RIFF", "media_file"),
        (b"fLaC", "media_file"),
        (b"OggS", "media_file"),
        (b"ID3", "media_file"),
        (b"\x00\x00\x01\xba", "media_file"),
        (b"\x00\x00\x01\xb3", "media_file"),
        (b"-----BEGIN PRIVATE KEY-----", "private_key"),
        (b"-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        (b"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key"),
        (b"-----BEGIN CERTIFICATE-----", "config_file"),
        (b"-----BEGIN PUBLIC KEY-----", "config_file"),
        (b"-----BEGIN PGP PRIVATE KEY BLOCK-----", "private_key"),
    ]
    for signature, kind in signatures:
        if data.startswith(signature):
            return kind
    # Common textual formats: only classify when the structure is clear.
    sample = data[:4096].lstrip()
    if sample.startswith((b"{", b"[")):
        try:
            json.loads(data.decode("utf-8"))
            return "structured_data_file"
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    if sample.startswith(b"<?xml") or sample.startswith(b"<html") or sample.startswith(b"<!DOCTYPE html"):
        return "structured_data_file"
    return None

def _read_local_file(value: Any) -> tuple[str | None, str | None, bytes | None]:
    """Return (path, input_type, bytes); never opens arbitrary non-path strings."""
    try:
        path = value if isinstance(value, Path) else Path(value) if isinstance(value, str) else None
        if path is None or not path.exists():
            return None, None, None
        if path.is_dir():
            names = {p.name.lower() for p in path.iterdir()}
            if any(n in names for n in ("history", "bookmarks", "cookies", "login data", "places.sqlite")):
                return str(path), "browser_profile", None
            if any(n.endswith((".evtx", ".reg", ".dat")) for n in names):
                return str(path), "triage_collection", None
            return str(path), "directory_tree", None
        if not path.is_file():
            return str(path), None, None
        suffixes = "".join(path.suffixes).lower()
        extension_type = next((kind for ext, kind in sorted(EXTENSION_TYPES.items(), key=lambda item: len(item[0]), reverse=True) if suffixes.endswith(ext)), None)
        try:
            with path.open("rb") as handle:
                head = handle.read(8192)
        except OSError:
            return str(path), extension_type, None
        return str(path), _magic_type(head) or extension_type, head
    except (OSError, ValueError, TypeError):
        return None, None, None

def _add_match(matches: list[dict[str, Any]], artefact_type: str, value: str,
               confidence: float, start: int | None, end: int | None,
               evidence: str) -> None:
    if not value:
        return
    key = (artefact_type, value.casefold(), start, end)
    if any((m["artefact_type"], m["value"].casefold(), m.get("start"), m.get("end")) == key for m in matches):
        return
    matches.append({
        "artefact_type": artefact_type,
        "value": value,
        "confidence": round(confidence, 3),
        "evidence": evidence,
        "start": start,
        "end": end,
    })

def _recognise_text(text: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []

    # Strong whole-input classifications take precedence for input_type, but
    # their contained artefacts are still collected below.
    for kind, pattern, confidence in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).strip().rstrip(".,;:!?)]}")
            if not value:
                continue
            if kind == "ip_address" and not _valid_ip(value):
                continue
            if kind == "ip_range" and not _valid_network(value):
                continue
            if kind == "domain":
                domain_kind = _domain_type(value)
                if not domain_kind:
                    continue
                kind = domain_kind
            _add_match(matches, kind, value, confidence, match.start(), match.start() + len(value), "pattern")
    # Explicitly parse host:port, including bracketed IPv6.
    for match in re.finditer(r"(?<!\S)(?:\[[0-9a-f:]+\]|[A-Za-z0-9.-]+):(\d{1,5})(?!\S)", text, re.I):
        value = match.group(0)
        try:
            host, port = value.rsplit(":", 1)
            if 0 <= int(port) <= 65535 and (host.startswith("[") or _domain_type(host) or _valid_ip(host)):
                _add_match(matches, "host_port", value, 0.95, match.start(), match.end(), "host_port")
        except ValueError:
            pass
    # Structured markers are useful artefacts in otherwise unclassified text.
    marker_patterns = [
        ("http_header", r"(?im)^(?:[A-Za-z][A-Za-z0-9-]{1,50}):\s*\S.*$"),
        ("dns_record", r"(?im)^\s*(?:\S+\s+)?(?:IN\s+)?(?:A|AAAA|CNAME|MX|NS|SOA|TXT|PTR|SRV|CAA)\s+\S.*$"),
        ("log_record", r"(?m)^\s*(?:\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d| \[[A-Z]+\]|\w+\s+\d{1,2}\s+\d\d:\d\d:\d\d).*$"),
        ("json_key_value", r'"[^"]+"\s*:\s*(?:".*?"|\d+|true|false|null|\{|\[)'),
        ("html_element", r"(?is)<(?:html|head|body|a|script|meta|link|form)\b[^>]*>"),
        ("git_reference", r"(?im)^\s*(?:commit|Author|Date):\s*.+$"),
        ("email_header", r"(?im)^(?:From|To|Cc|Bcc|Subject|Date|Message-ID|Received|Return-Path):\s*.+$"),
    ]
    for kind, expression in marker_patterns:
        for match in re.finditer(expression, text):
            _add_match(matches, kind, match.group(0).strip(), 0.82, match.start(), match.end(), "structure")
    return sorted(matches, key=lambda m: (m["start"] is None, m["start"] if m["start"] is not None else -1, m["artefact_type"]))

def _classify_string(value: str, path_type: str | None = None) -> tuple[str | None, float, str]:
    stripped = value.strip()
    if not stripped:
        return None, 0.0, "empty input"
    if path_type:
        return path_type, 0.99, "local filesystem inspection"
    if _looks_like_url(stripped):
        parts = urlsplit(stripped)
        if parts.hostname and parts.hostname.lower() in {"github.com", "gitlab.com", "bitbucket.org"} and len([p for p in parts.path.split("/") if p]) >= 2:
            return "git_repository_url", 0.98, "repository URL structure"
        if re.search(r"/(?:openapi|swagger|api-docs|graphql)(?:[./?#]|$)", stripped, re.I):
            return "api_spec_url", 0.90, "API specification URL pattern"
        if re.search(r"/(?:press|news|releases?)(?:/|$)", parts.path, re.I):
            return "press_release_url", 0.68, "URL path pattern"
        if re.search(r"/(?:jobs?|careers?)(?:/|$)", parts.path, re.I):
            return "job_ad_url", 0.68, "URL path pattern"
        if re.search(r"(?:google\.[^/]+/maps|maps\.apple\.com|openstreetmap\.org)", parts.netloc, re.I):
            return "map_url", 0.97, "map URL host"
        return "url", 0.99, "URL scheme and authority"
    if _valid_network(stripped):
        return "ip_range", 0.99, "IP network parser"
    if _valid_ip(stripped):
        return "ip_address", 0.99, "IP address parser"
    if re.fullmatch(r"(?:AS|ASN)\s*\d{1,10}", stripped, re.I):
        return "asn", 0.99, "ASN syntax"
    if re.fullmatch(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", stripped, re.I):
        return "email_address", 0.99, "email syntax"
    if re.fullmatch(r"[0-9A-Fa-f]{32}", stripped):
        return "file_hash", 0.76, "32-character hexadecimal digest; type is ambiguous"
    if re.fullmatch(r"[0-9A-Fa-f]{40}", stripped):
        return "file_hash", 0.82, "40-character hexadecimal digest; could also be a commit hash"
    if re.fullmatch(r"[0-9A-Fa-f]{64}", stripped):
        return "file_hash", 0.82, "64-character hexadecimal digest"
    if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", stripped):
        return "cve_id", 0.99, "CVE syntax"
    if re.fullmatch(r"(?i)pkg:[a-z][a-z0-9.+-]*/\S+", stripped):
        return "package_reference", 0.99, "package URL syntax"
    if re.fullmatch(r"(?i)SHA256:[A-Za-z0-9+/]{20,}={0,2}", stripped):
        return "ssh_fingerprint", 0.99, "SSH SHA-256 fingerprint syntax"
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", stripped):
        return "mac_address", 0.98, "hardware address syntax"
    if re.fullmatch(r"[A-Za-z0-9._-]{2,32}", stripped) and stripped.startswith("@"):
        return "username", 0.82, "handle syntax"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ][0-2]\d:[0-5]\d(?::[0-6]\d)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?", stripped):
        return "timestamp_or_time_range", 0.95, "timestamp syntax"
    if re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{3}[\dX]", stripped, re.I):
        return "academic_identifier", 0.99, "ORCID syntax"
    domain_kind = _domain_type(stripped)
    if domain_kind:
        return domain_kind, 0.94, "domain-name syntax"
    if re.fullmatch(r"\d{1,5}", stripped):
        return None, 0.0, "bare number is ambiguous"
    # Explicit case/scope object is supported by the dict path, not a bare
    # string. A phrase is accepted only as a keyword when it is clearly phrase-like.
    words = stripped.split()
    if len(words) >= 2 and len(stripped) <= 160 and not re.search(r"[<>{}\[\]]", stripped):
        if len(words) <= 8 and not re.search(r"(?i)\b(?:error|exception|traceback|received:|user-agent:|authorization:|content-type:|from:|to:|subject:)\b", stripped):
            return "keyword_phrase", 0.62, "plain-text phrase; semantic category is not inferable locally"
        return "free_text_blob", 0.76, "multi-token text blob"
    # One-word values can be usernames, names, company names, tickers, places,
    # packages, or keywords. Reject rather than silently guess.
    return None, 0.0, "single token is ambiguous without a type hint"

def _classify_mapping(value: dict[str, Any]) -> tuple[str | None, float, str, Any]:
    """Classify explicitly typed input envelopes without guessing their schema."""
    explicit = value.get("input_type") or value.get("type")
    if isinstance(explicit, str):
        normalised = explicit.strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "ip": "ip_address", "ipv4": "ip_address", "ipv6": "ip_address",
            "cidr": "ip_range", "email": "email_address", "handle": "username",
            "text": "free_text_blob", "blob": "free_text_blob",
            "path": "directory_tree", "file": "structured_data_file",
            "scope": "case_scope", "context": "case_scope",
        }
        normalised = aliases.get(normalised, normalised)
        if normalised in INPUT_TYPES:
            return normalised, 0.99, "explicit input_type/type field", value.get("value", value.get("input", value))
    if any(key in value for key in ("authorisation", "authorization", "allowed_sources", "scope", "depth")):
        return "case_scope", 0.92, "case/scope context keys", value
    return None, 0.0, "mapping lacks a recognised explicit type", value

class Identifier:
    """Classifies one main.py input and recognises artefacts within it."""

    def identify(self, value: Any) -> Packet:
        safe_value = _safe_input(value)
        input_type: str | None = None
        confidence = 0.0
        rationale = ""
        text: str | None = None
        path: str | None = None
        file_head: bytes | None = None

        if isinstance(value, dict):
            input_type, confidence, rationale, payload = _classify_mapping(value)
            if isinstance(payload, str):
                text = payload
            elif isinstance(payload, bytes):
                text = payload.decode("utf-8", errors="replace")
            elif isinstance(payload, (dict, list)):
                text = json.dumps(payload, ensure_ascii=False, default=str)
            else:
                text = str(payload) if payload is not None else None
        elif isinstance(value, bytes):
            file_head = value[:8192]
            input_type = _magic_type(value)
            confidence = 0.96 if input_type else 0.0
            rationale = "file signature" if input_type else "unrecognised byte content"
            text = value.decode("utf-8", errors="replace") if input_type is None else None
            if input_type is None and text and _is_textual(text):
                input_type, confidence, rationale = "free_text_blob", 0.75, "UTF-8-decodable text blob"
        elif isinstance(value, (str, Path)):
            raw = str(value)
            path, path_type, file_head = _read_local_file(value)
            input_type, confidence, rationale = _classify_string(raw, path_type)
            if path and path_type:
                # Use readable file contents for embedded artefact recognition.
                try:
                    p = Path(path)
                    if p.is_file() and p.stat().st_size <= 2_000_000:
                        raw_bytes = p.read_bytes()
                        if _magic_type(raw_bytes[:8192]) is None:
                            text = raw_bytes.decode("utf-8", errors="replace")
                        elif p.suffix.lower() in {".json", ".jsonl", ".csv", ".tsv", ".xml", ".yaml", ".yml", ".log", ".txt", ".eml", ".har", ".warc"}:
                            text = raw_bytes.decode("utf-8", errors="replace")
                except (OSError, ValueError):
                    pass
            else:
                text = raw
        else:
            input_type, confidence, rationale, _ = None, 0.0, "unsupported Python input object", None

        matches: list[dict[str, Any]] = []
        if text is not None:
            matches = _recognise_text(text)
        elif file_head:
            detected = _magic_type(file_head)
            if detected:
                matches.append({
                    "artefact_type": detected, "value": path or "[supplied bytes]",
                    "confidence": 0.96, "evidence": "file signature",
                    "start": None, "end": None,
                })

        # A strong whole-input classification should itself appear as a match.
        if input_type and input_type not in {"free_text_blob", "keyword_phrase", "case_scope", "directory_tree", "browser_profile", "triage_collection"}:
            raw_value = str(value) if isinstance(value, (str, Path)) else None
            if raw_value and not path:
                _add_match(matches, input_type, raw_value.strip(), confidence, 0, len(raw_value.strip()), rationale)

        # A directory is represented as a collection-level artefact. The
        # identifier does not recursively traverse it or read unrelated files.
        if input_type in {"directory_tree", "browser_profile", "triage_collection"}:
            _add_match(matches, input_type, path or str(value), confidence, None, None, rationale)

        if input_type is None or confidence < 0.60:
            packet = Packet(
                stage="identification",
                artefact_type="input",
                input=safe_value,
                status=PacketStatus.NOT_SUPPORTED,
                data={
                    "input_type": None,
                    "confidence": round(confidence, 3),
                    "matches": matches,
                    "classification": {"accepted": False, "reason": rationale},
                },
                metadata={"component": "core.identifier", "version": "1.0"},
            )
            packet.add_error(
                code="unsupported_input_type",
                message=f"Input could not be reliably classified: {rationale}. Supply a recognised identifier, supported file, or an explicit {'input_type' if isinstance(value, dict) else 'type hint'}.",
                component="core.identifier",
            )
            return packet

        return Packet(
            stage="identification",
            artefact_type="input",
            input=safe_value,
            status=PacketStatus.SUCCESS,
            data={
                "input_type": input_type,
                "confidence": round(confidence, 3),
                "matches": matches,
                "classification": {"accepted": True, "reason": rationale},
            },
            metadata={"component": "core.identifier", "version": "1.0"},
        )

    __call__ = identify

def _is_textual(value: str) -> bool:
    if not value:
        return False
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in value)
    return printable / len(value) >= 0.90

def identify(value: Any) -> Packet:
    """Convenience function used by main.py."""
    return Identifier().identify(value)

__all__ = ["Identifier", "INPUT_TYPES", "identify"]