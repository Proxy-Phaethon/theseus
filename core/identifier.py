from __future__ import annotations

import ipaddress
import json
import re

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class ArtefactType(str, Enum):
    # Web and browser
    URL = "url"
    HTML_SOURCE = "html_source"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    HTTP_HEADERS = "http_headers"
    JAVASCRIPT = "javascript"
    CSS = "css"
    WEB_MANIFEST = "web_manifest"
    ROBOTS_TXT = "robots_txt"
    SITEMAP = "sitemap"
    WEB_ARCHIVE_RECORD = "web_archive_record"
    BROWSER_HISTORY = "browser_history"
    BROWSER_BOOKMARKS = "browser_bookmarks"
    COOKIE_DATA = "cookie_data"
    WEB_STORAGE = "web_storage"

    # Identity and communications
    EMAIL_ADDRESS = "email_address"
    EMAIL_MESSAGE = "email_message"
    EMAIL_HEADERS = "email_headers"
    EMAIL_DELIVERY_REPORT = "email_delivery_report"
    PHONE_NUMBER = "phone_number"
    SOCIAL_PROFILE = "social_profile"
    CHAT_EXPORT = "chat_export"
    VCARD = "vcard"
    CALENDAR_INVITE = "calendar_invite"

    # Internet infrastructure
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    REVERSE_IP_RESULT = "reverse_ip_result"
    DNS_RECORDS = "dns_records"
    WHOIS_RECORD = "whois_record"
    RDAP_RECORD = "rdap_record"
    TLS_CERTIFICATE = "tls_certificate"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    ASN_RECORD = "asn_record"
    BGP_RECORD = "bgp_record"
    SERVICE_BANNER = "service_banner"
    SSH_HOST_KEY = "ssh_host_key"
    THREAT_INTELLIGENCE_INDICATOR = "threat_intelligence_indicator"

    # Files and documents
    PDF_DOCUMENT = "pdf_document"
    OFFICE_DOCUMENT = "office_document"
    CSV_DATA = "csv_data"
    JSON_DATA = "json_data"
    JSONL_DATA = "jsonl_data"
    XML_DATA = "xml_data"
    YAML_DATA = "yaml_data"
    SQL_DATA = "sql_data"
    ARCHIVE_FILE = "archive_file"
    EXECUTABLE_FILE = "executable_file"
    FILE_HASH = "file_hash"
    FILE_METADATA = "file_metadata"
    DIGITAL_SIGNATURE = "digital_signature"
    IMAGE_METADATA = "image_metadata"
    AUDIO_VIDEO_METADATA = "audio_video_metadata"

    # Operating systems and endpoint artefacts
    WINDOWS_EVENT_LOG = "windows_event_log"
    WINDOWS_REGISTRY = "windows_registry"
    WINDOWS_SHORTCUT = "windows_shortcut"
    MACOS_PLIST = "macos_plist"
    MACOS_UNIFIED_LOG = "macos_unified_log"
    LINUX_SYSTEM_LOG = "linux_system_log"
    SHELL_HISTORY = "shell_history"
    SSH_CONFIGURATION = "ssh_configuration"
    PROCESS_LIST = "process_list"
    SERVICE_CONFIGURATION = "service_configuration"
    AUTHENTICATION_LOG = "authentication_log"

    # Network and packet capture
    PCAP_CAPTURE = "pcap_capture"
    NETWORK_FLOW = "network_flow"
    FIREWALL_LOG = "firewall_log"
    DHCP_RECORD = "dhcp_record"
    ARP_RECORD = "arp_record"
    WIFI_CONFIGURATION = "wifi_configuration"

    # Authentication and secrets
    JWT_TOKEN = "jwt_token"
    SSH_PRIVATE_KEY = "ssh_private_key"
    SSH_PUBLIC_KEY = "ssh_public_key"
    API_KEY = "api_key"
    ENVIRONMENT_CONFIGURATION = "environment_configuration"
    OAUTH_CONFIGURATION = "oauth_configuration"
    PASSWORD_HASH = "password_hash"
    SECRET_SCAN_FINDING = "secret_scan_finding"

    # Software and development
    GIT_COMMIT = "git_commit"
    GIT_REPOSITORY = "git_repository"
    PACKAGE_MANIFEST = "package_manifest"
    LOCKFILE = "lockfile"
    CONTAINER_CONFIGURATION = "container_configuration"
    CI_CD_CONFIGURATION = "ci_cd_configuration"
    API_SPECIFICATION = "api_specification"
    SOFTWARE_BILL_OF_MATERIALS = "software_bill_of_materials"
    APPLICATION_LOG = "application_log"

    # Databases, cloud and enterprise
    SQLITE_DATABASE = "sqlite_database"
    DATABASE_DUMP = "database_dump"
    CLOUD_CONFIGURATION = "cloud_configuration"
    CLOUD_AUDIT_LOG = "cloud_audit_log"
    DIRECTORY_EXPORT = "directory_export"
    RESOURCE_INVENTORY = "resource_inventory"

    # Public records and research
    CORPORATE_FILING = "corporate_filing"
    PATENT_RECORD = "patent_record"
    TRADEMARK_RECORD = "trademark_record"
    COURT_RECORD = "court_record"
    PROCUREMENT_RECORD = "procurement_record"
    PUBLICATION_RECORD = "publication_record"

    # Geospatial and multimedia
    GPS_COORDINATES = "gps_coordinates"
    GEOJSON_DATA = "geojson_data"
    GPX_DATA = "gpx_data"
    KML_DATA = "kml_data"
    SUBTITLE_DATA = "subtitle_data"
    OCR_TEXT = "ocr_text"
    TRANSCRIPT = "transcript"

    # General structured artefacts
    TIMESTAMP = "timestamp"
    MAC_ADDRESS = "mac_address"
    UUID = "uuid"
    PUBLIC_KEY_FINGERPRINT = "public_key_fingerprint"

    UNIDENTIFIED = "unidentified"

@dataclass(frozen=True, slots=True)
class ArtefactMatch:
    """One classification supported by observable evidence."""

    artefact_type: ArtefactType
    confidence: float
    evidence: str
    start: int | None = None
    end: int | None = None

@dataclass(slots=True)
class IdentificationResult:
    """Classification of an input before investigation begins."""

    input_data: str | bytes
    matches: list[ArtefactMatch] = field(default_factory=list)
    source_hint: str | None = None
    error: str | None = None

    @property
    def identified(self) -> bool:
        return any(
            match.artefact_type != ArtefactType.UNIDENTIFIED
            for match in self.matches
        )

    @property
    def artefact_types(self) -> list[ArtefactType]:
        return list(dict.fromkeys(
            match.artefact_type
            for match in self.matches
        ))

# Each rule detects a recognisable signature, not merely a possible keyword.
_PATTERNS: tuple[
    tuple[ArtefactType, re.Pattern[str], float], ...
] = (
    (
        ArtefactType.EMAIL_ADDRESS,
        re.compile(
            r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+"
            r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)"
            r"[A-Za-z]{2,63}(?![\w.-])"
        ),
        0.99,
    ),
    (
        ArtefactType.URL,
        re.compile(
            r"https?://[^\s<>\"']+",
            re.IGNORECASE,
        ),
        0.99,
    ),
    (
        ArtefactType.JWT_TOKEN,
        re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"eyJ[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+"
            r"(?![A-Za-z0-9_-])"
        ),
        0.98,
    ),
    (
        ArtefactType.FILE_HASH,
        re.compile(
            r"(?<![A-Fa-f0-9])"
            r"(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|"
            r"[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|"
            r"[A-Fa-f0-9]{128})"
            r"(?![A-Fa-f0-9])"
        ),
        0.96,
    ),
    (
        ArtefactType.MAC_ADDRESS,
        re.compile(
            r"(?<![\w])"
            r"(?:[0-9A-Fa-f]{2}[:-]){5}"
            r"[0-9A-Fa-f]{2}"
            r"(?![\w])"
        ),
        0.99,
    ),
    (
        ArtefactType.UUID,
        re.compile(
            r"(?<![0-9A-Fa-f])"
            r"[0-9A-Fa-f]{8}-"
            r"[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{12}"
            r"(?![0-9A-Fa-f])"
        ),
        0.99,
    ),
    (
        ArtefactType.GPS_COORDINATES,
        re.compile(
            r"(?<![\d.])"
            r"-?(?:[0-8]?\d(?:\.\d+)?|90(?:\.0+)?)"
            r"\s*[,;]\s*"
            r"-?(?:1[0-7]\d(?:\.\d+)?|"
            r"\d?\d(?:\.\d+)?|180(?:\.0+)?)"
            r"(?![\d.])"
        ),
        0.80,
    ),
    (
        ArtefactType.SSH_PRIVATE_KEY,
        re.compile(
            r"-----BEGIN "
            r"(?:OPENSSH|RSA|DSA|EC|ENCRYPTED) PRIVATE KEY-----"
        ),
        0.99,
    ),
    (
        ArtefactType.SSH_PUBLIC_KEY,
        re.compile(
            r"(?m)^\s*(?:ssh-rsa|ssh-ed25519|"
            r"ecdsa-sha2-[A-Za-z0-9-]+)\s+[A-Za-z0-9+/=]+"
        ),
        0.99,
    ),
    (
        ArtefactType.TLS_CERTIFICATE,
        re.compile(
            r"-----BEGIN CERTIFICATE-----"
        ),
        0.99,
    ),
    (
        ArtefactType.SSH_HOST_KEY,
        re.compile(
            r"(?im)^\s*(?:[A-Za-z0-9.-]+[,\s]+)?"
            r"(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-[\w-]+)"
            r"\s+[A-Za-z0-9+/=]+"
        ),
        0.90,
    ),
    (
        ArtefactType.WEB_MANIFEST,
        re.compile(
            r'"(?:name|short_name|start_url|display)"\s*:',
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        ArtefactType.ROBOTS_TXT,
        re.compile(
            r"(?im)^\s*(?:User-agent|Disallow|Allow|"
            r"Sitemap|Crawl-delay)\s*:"
        ),
        0.90,
    ),
    (
        ArtefactType.SITEMAP,
        re.compile(
            r"<(?:\w+:)?(?:urlset|sitemapindex)\b",
            re.IGNORECASE,
        ),
        0.99,
    ),
    (
        ArtefactType.HTML_SOURCE,
        re.compile(
            r"(?is)<!doctype\s+html\b|<html\b|"
            r"<head\b.{0,200}<body\b|<body\b"
        ),
        0.98,
    ),
    (
        ArtefactType.CSS,
        re.compile(
            r"(?s)(?:^|\})\s*(?:@media\b|"
            r"@import\b|@font-face\b|"
            r"[-.#][A-Za-z_][\w-]*\s*\{[^}]*:"
            r"|[A-Za-z-]+\s*:\s*[^;{}]+;)"
        ),
        0.70,
    ),
    (
        ArtefactType.JAVASCRIPT,
        re.compile(
            r"(?s)(?:\b(?:const|let|var)\s+\w+\s*=|"
            r"\bfunction\s+\w*\s*\(|"
            r"=>\s*\{|"
            r"\b(?:document|window)\.[A-Za-z_$])"
        ),
        0.78,
    ),
    (
        ArtefactType.HTTP_REQUEST,
        re.compile(
            r"(?im)^\s*(?:GET|POST|PUT|PATCH|DELETE|"
            r"HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+"
            r"HTTP/\d(?:\.\d)?\s*$"
        ),
        0.99,
    ),
    (
        ArtefactType.HTTP_RESPONSE,
        re.compile(
            r"(?im)^\s*HTTP/\d(?:\.\d)?\s+\d{3}\b"
        ),
        0.99,
    ),
    (
        ArtefactType.EMAIL_HEADERS,
        re.compile(
            r"(?im)^(?:From|To|Subject|Date|Message-ID|"
            r"Return-Path|Received|DKIM-Signature|"
            r"Authentication-Results):\s*.+"
        ),
        0.87,
    ),
    (
        ArtefactType.EMAIL_DELIVERY_REPORT,
        re.compile(
            r"(?is)Reporting-MTA:|Final-Recipient:|"
            r"Action:\s*(?:failed|delayed|delivered)|"
            r"Diagnostic-Code:"
        ),
        0.94,
    ),
    (
        ArtefactType.RDAP_RECORD,
        re.compile(
            r'"(?:objectClassName|handle|events|'
            r'entities|nameservers|rdapConformance)"\s*:'
        ),
        0.88,
    ),
    (
        ArtefactType.DNS_RECORDS,
        re.compile(
            r"(?im)^\s*\S+\.?\s+"
            r"(?:\d+\s+IN\s+)?"
            r"(?:A|AAAA|MX|NS|SOA|CNAME|TXT|PTR|"
            r"SRV|CAA|DS|DNSKEY)\s+"
        ),
        0.95,
    ),
    (
        ArtefactType.WHOIS_RECORD,
        re.compile(
            r"(?im)^(?:Domain Name|Registrar|"
            r"Creation Date|Registry Expiry Date|"
            r"Name Server|Registrant Organization):\s*.+"
        ),
        0.94,
    ),
    (
        ArtefactType.REVERSE_IP_RESULT,
        re.compile(
            r"(?is)(?:reverse[\s_-]*ip|"
            r"domains?\s+(?:hosted|resolving)\s+on|"
            r"hosted\s+domains?\s*:|"
            r"reverse\s+lookup\s+results?)"
        ),
        0.96,
    ),
    (
        ArtefactType.ASN_RECORD,
        re.compile(
            r"(?im)\bAS\d{1,10}\b"
        ),
        0.78,
    ),
    (
        ArtefactType.BGP_RECORD,
        re.compile(
            r"(?im)^\s*(?:BGP\s+)?"
            r"(?:route|origin|next-hop|as-path|"
            r"prefix|local-pref)\s*[:=]"
        ),
        0.87,
    ),
    (
        ArtefactType.SERVICE_BANNER,
        re.compile(
            r"(?im)^(?:SSH-\d\.\d-|"
            r"220[- ].*(?:ESMTP|FTP|SMTP)|"
            r"\+OK\b|"
            r"Server:\s*\S+|"
            r"OpenSSH_\d)"
        ),
        0.88,
    ),
    (
        ArtefactType.PDF_DOCUMENT,
        re.compile(r"%PDF-\d\.\d"),
        0.99,
    ),
    (
        ArtefactType.WINDOWS_SHORTCUT,
        re.compile(r"(?s)^L\x00\x00\x00\x01\x14\x02\x00"),
        0.99,
    ),
    (
        ArtefactType.SQL_DATA,
        re.compile(
            r"(?im)^\s*(?:CREATE\s+TABLE|INSERT\s+INTO|"
            r"ALTER\s+TABLE|CREATE\s+DATABASE|"
            r"BEGIN\s+TRANSACTION)\b"
        ),
        0.89,
    ),
    (
        ArtefactType.SHELL_HISTORY,
        re.compile(
            r"(?m)^\s*(?:sudo\s+\S+|"
            r"(?:git|curl|wget|ssh|nmap|python|pip)\s+"
            r"\S+.*)$"
        ),
        0.60,
    ),
    (
        ArtefactType.GIT_COMMIT,
        re.compile(
            r"(?m)^(?:commit\s+[0-9a-f]{7,64}|"
            r"Author:\s+.+\s+<[^>]+>|"
            r"Date:\s+.+)$"
        ),
        0.91,
    ),
    (
        ArtefactType.GIT_REPOSITORY,
        re.compile(
            r"(?im)^(?:\[remote\s+\"origin\"\]|"
            r"remote\.origin\.url\s*=|"
            r"ref:\s+refs/heads/)"
        ),
        0.94,
    ),
    (
        ArtefactType.PACKAGE_MANIFEST,
        re.compile(
            r'"(?:dependencies|devDependencies|scripts)"\s*:'
        ),
        0.72,
    ),
    (
        ArtefactType.LOCKFILE,
        re.compile(
            r"(?im)^(?:lockfileVersion:|"
            r"version\s*=\s*\d+|"
            r"__metadata:|"
            r'"lockfileVersion"\s*:)' 
        ),
        0.80,
    ),
    (
        ArtefactType.APPLICATION_LOG,
        re.compile(
            r"(?im)^\d{4}-\d\d-\d\d[T ]"
            r"\d\d:\d\d:\d\d(?:\.\d+)?"
            r"(?:Z|[+-]\d\d:?\d\d)?\s+"
            r"(?:DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL)\b"
        ),
        0.82,
    ),
    (
        ArtefactType.WINDOWS_EVENT_LOG,
        re.compile(
            r"(?is)<Event\b[^>]*>.*?"
            r"<System>.*?<EventID>\d+</EventID>"
        ),
        0.96,
    ),
    (
        ArtefactType.MACOS_PLIST,
        re.compile(
            r"(?s)<\?xml[^>]*\?>\s*"
            r"<!DOCTYPE plist\b|"
            r"<plist\b"
        ),
        0.97,
    ),
    (
        ArtefactType.GEOJSON_DATA,
        re.compile(
            r'"type"\s*:\s*"(?:FeatureCollection|Feature|'
            r'Point|MultiPoint|LineString|MultiLineString|'
            r'Polygon|MultiPolygon)"'
        ),
        0.84,
    ),
    (
        ArtefactType.GPX_DATA,
        re.compile(r"<(?:\w+:)?gpx\b", re.IGNORECASE),
        0.99,
    ),
    (
        ArtefactType.KML_DATA,
        re.compile(r"<(?:\w+:)?kml\b", re.IGNORECASE),
        0.99,
    ),
    (
        ArtefactType.SUBTITLE_DATA,
        re.compile(
            r"(?m)^\d{2}:\d{2}:\d{2}[,.]\d{3}\s+-->\s+"
        ),
        0.96,
    ),
)

def _decode(data: str | bytes) -> str:
    """Convert input to text without discarding undecodable bytes."""
    if isinstance(data, str):
        return data

    return data.decode("utf-8", errors="replace")

def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _is_domain(value: str) -> bool:
    """Conservatively validate a standalone DNS hostname."""
    value = value.rstrip(".").lower()

    if not value or len(value) > 253 or "." not in value:
        return False

    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass

    labels = value.split(".")

    return all(
        1 <= len(label) <= 63
        and re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
            label,
        ) is not None
        for label in labels
    ) and bool(re.fullmatch(r"[a-z]{2,63}", labels[-1]))

def classify(
    data: str | bytes,
    *,
    source_hint: str | None = None,
) -> IdentificationResult:
    """Identify every artefact type supported by observable signatures.

    The input is treated as supplied content. This function does not fetch
    URLs, open files, execute code, or contact external services.
    """
    text = _decode(data)
    result = IdentificationResult(
        input_data=data,
        source_hint=source_hint,
    )

    def add(
        artefact_type: ArtefactType,
        confidence: float,
        evidence: str,
        start: int | None = None,
        end: int | None = None,
    ) -> None:
        if any(
            item.artefact_type == artefact_type
            and item.start == start
            and item.end == end
            for item in result.matches
        ):
            return

        result.matches.append(
            ArtefactMatch(
                artefact_type=artefact_type,
                confidence=confidence,
                evidence=evidence,
                start=start,
                end=end,
            )
        )

    if not text.strip():
        result.error = "Empty input."
        add(ArtefactType.UNIDENTIFIED, 1.0, "Input is empty.")
        return result

    # Binary signatures must be checked against the original bytes.
    if isinstance(data, bytes):
        if data.startswith(b"PCAP"):
            add(ArtefactType.PCAP_CAPTURE, 0.99, "PCAP file signature")
        elif data.startswith(
            (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
             b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        ):
            add(ArtefactType.PCAP_CAPTURE, 0.99, "PCAP file magic")
        elif data.startswith(b"SQLite format 3\x00"):
            add(ArtefactType.SQLITE_DATABASE, 0.99, "SQLite file signature")
        elif data.startswith(b"PK\x03\x04"):
            add(ArtefactType.ARCHIVE_FILE, 0.98, "ZIP container signature")
            add(
                ArtefactType.OFFICE_DOCUMENT,
                0.65,
                "ZIP container; may contain an Office document",
            )
        elif data.startswith(b"\x7fELF"):
            add(ArtefactType.EXECUTABLE_FILE, 0.99, "ELF file signature")
        elif data.startswith(b"MZ"):
            add(ArtefactType.EXECUTABLE_FILE, 0.92, "DOS/Windows executable signature")
        elif data.startswith(b"\x1f\x8b"):
            add(ArtefactType.ARCHIVE_FILE, 0.99, "GZIP file signature")
        elif data.startswith(b"Rar!\x1a\x07"):
            add(ArtefactType.ARCHIVE_FILE, 0.99, "RAR file signature")
        elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
            add(ArtefactType.ARCHIVE_FILE, 0.99, "7-Zip file signature")

    # Source hints express known provenance and disambiguate similar formats.
    hint = (source_hint or "").strip().lower().replace("-", "_")

    hint_types = {
        "reverse_ip": ArtefactType.REVERSE_IP_RESULT,
        "reverse_ip_result": ArtefactType.REVERSE_IP_RESULT,
        "browser_history": ArtefactType.BROWSER_HISTORY,
        "browser_bookmarks": ArtefactType.BROWSER_BOOKMARKS,
        "windows_registry": ArtefactType.WINDOWS_REGISTRY,
        "windows_event_log": ArtefactType.WINDOWS_EVENT_LOG,
        "linux_system_log": ArtefactType.LINUX_SYSTEM_LOG,
        "firewall_log": ArtefactType.FIREWALL_LOG,
        "network_flow": ArtefactType.NETWORK_FLOW,
        "whois": ArtefactType.WHOIS_RECORD,
        "rdap": ArtefactType.RDAP_RECORD,
        "dns": ArtefactType.DNS_RECORDS,
        "pcap": ArtefactType.PCAP_CAPTURE,
        "email": ArtefactType.EMAIL_MESSAGE,
        "email_message": ArtefactType.EMAIL_MESSAGE,
        "html": ArtefactType.HTML_SOURCE,
        "http_request": ArtefactType.HTTP_REQUEST,
        "http_response": ArtefactType.HTTP_RESPONSE,
        "jsonl": ArtefactType.JSONL_DATA,
        "yaml": ArtefactType.YAML_DATA,
        "gpx": ArtefactType.GPX_DATA,
        "kml": ArtefactType.KML_DATA,
    }

    if hint in hint_types:
        add(
            hint_types[hint],
            0.99,
            f"Artefact type supplied by source hint: {source_hint}",
        )

    # Signature and structure rules. Multiple matches are intentional.
    for artefact_type, pattern, confidence in _PATTERNS:
        match = pattern.search(text)

        if match:
            add(
                artefact_type,
                confidence,
                match.group(0).strip()[:200],
                match.start(),
                match.end(),
            )

    # JSON, JSONL, XML, and YAML require structural checks.
    stripped = text.strip()

    try:
        parsed: Any = json.loads(stripped)

        if isinstance(parsed, (dict, list)):
            if not any(
                match.artefact_type == ArtefactType.GEOJSON_DATA
                for match in result.matches
            ):
                add(
                    ArtefactType.JSON_DATA,
                    0.99,
                    "Input parses as a JSON object or array",
                )

            if isinstance(parsed, dict):
                if any(
                    key in parsed
                    for key in ("type", "features", "geometry", "coordinates")
                ):
                    if parsed.get("type") in {
                        "Feature", "FeatureCollection", "Point",
                        "MultiPoint", "LineString", "MultiLineString",
                        "Polygon", "MultiPolygon",
                    }:
                        add(
                            ArtefactType.GEOJSON_DATA,
                            0.98,
                            "JSON has a GeoJSON geometry type",
                        )

    except (json.JSONDecodeError, ValueError):
        # JSONL is a sequence of independently valid JSON values.
        lines = [line.strip() for line in stripped.splitlines() if line.strip()]

        if len(lines) > 1:
            try:
                for line in lines:
                    json.loads(line)
            except (json.JSONDecodeError, ValueError):
                pass
            else:
                add(
                    ArtefactType.JSONL_DATA,
                    0.97,
                    "Each non-empty line parses as JSON",
                )

    if re.search(r"(?is)^\s*(?:<\?xml\b|<[\w:.-]+(?:\s|>))", stripped):
        if re.search(r"(?is)<\?xml\b|</[\w:.-]+>", stripped):
            add(
                ArtefactType.XML_DATA,
                0.88,
                "XML declaration or matching element structure",
            )

    # IPs and domains are entities that may occur inside larger artefacts.
    for match in re.finditer(
        r"(?<![A-Za-z0-9_.:-])"
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"(?![A-Za-z0-9_.:-])",
        text,
    ):
        value = match.group(0)

        if _valid_ip(value):
            add(
                ArtefactType.IP_ADDRESS,
                0.99,
                value,
                match.start(),
                match.end(),
            )

    for match in re.finditer(
        r"(?<![@\w-])"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}"
        r"(?![\w-])",
        text,
    ):
        value = match.group(0)

        if _is_domain(value):
            add(
                ArtefactType.DOMAIN,
                0.94,
                value,
                match.start(),
                match.end(),
            )

    # A single URL or email address is itself an identifiable artefact.
    # Plain words and unrecognised strings are not silently promoted.
    if not result.identified:
        result.error = (
            "Unable to identify the input from its content or supplied "
            "source hint."
        )
        add(
            ArtefactType.UNIDENTIFIED,
            1.0,
            result.error,
        )

    return result

def identify(
    data: str | bytes,
    *,
    source_hint: str | None = None,
) -> Any:
    """Classify input and forward the result to the executor."""
    result = classify(data, source_hint=source_hint)

    # Kept local so classification can be tested independently.
    from core.executor import execute

    return execute(result)