"""Artefact identification for Theseus.

Accepts arbitrary text or bytes, identifies recognisable artefact types,
and returns a standard Packet for the executor.

No external dependencies.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from uuid import uuid4
from urllib.parse import urlparse

from core.packets import Packet, PacketStatus

@dataclass(frozen=True)
class ArtefactMatch:
    """A recognised artefact and the evidence supporting its classification."""

    artefact_type: str
    confidence: float
    evidence: str
    start: int | None = None
    end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "artefact_type": self.artefact_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "start": self.start,
            "end": self.end,
        }

# Patterns identify candidate artefacts. Structural validation is applied
# where practical to reduce false positives.
PATTERNS: dict[str, re.Pattern[str]] = {
    "email_address": re.compile(
        r"(?<![\w.+-])"
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
        r"(?![\w.-])"
    ),
    "url": re.compile(
        r"""(?i)\b(?:https?|ftp)://[^\s<>"']+"""
    ),
    "ipv4_address": re.compile(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
    ),
    "ipv6_candidate": re.compile(
        r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}"
        r"[0-9a-fA-F]{0,4}(?![\w:])"
    ),
    "mac_address": re.compile(
        r"(?i)(?<![\da-f])"
        r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"
        r"(?![\da-f])"
    ),
    "uuid": re.compile(
        r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-"
        r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
        r"[0-9a-f]{12}\b"
    ),
    "jwt_token": re.compile(
        r"(?<![\w-])"
        r"eyJ[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+"
        r"(?![\w-])"
    ),
    "timestamp_iso8601": re.compile(
        r"\b\d{4}-\d{2}-\d{2}"
        r"(?:[Tt ]\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?)?\b"
    ),
    "domain": re.compile(
        r"(?i)(?<![@\w-])"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
        r"(?![\w-])"
    ),
}

# Common file signatures. These are signatures, not full file validation.
MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "pdf_document"),
    (b"\x89PNG\r\n\x1a\n", "image_file"),
    (b"\xff\xd8\xff", "image_file"),
    (b"GIF87a", "image_file"),
    (b"GIF89a", "image_file"),
    (b"PK\x03\x04", "zip_archive"),
    (b"\x1f\x8b", "gzip_archive"),
    (b"SQLite format 3\x00", "sqlite_database"),
    (b"\x7fELF", "executable_file"),
    (b"MZ", "executable_file"),
    (b"-----BEGIN CERTIFICATE-----", "tls_certificate"),
    (b"-----BEGIN PUBLIC KEY-----", "public_key"),
    (b"-----BEGIN PRIVATE KEY-----", "private_key"),
    (b"-----BEGIN RSA PRIVATE KEY-----", "private_key"),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key"),
    (b"-----BEGIN OPENSSH PUBLIC KEY-----", "public_key"),
)

def _decode_text(value: str | bytes) -> str | None:
    """Decode bytes when they appear to contain text."""

    if isinstance(value, str):
        return value

    if not isinstance(value, bytes):
        raise TypeError("Identifier input must be str or bytes.")

    if b"\x00" in value[:8192]:
        return None

    try:
        return value.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return value.decode("latin-1")
        except UnicodeDecodeError:
            return None

def _valid_domain(value: str) -> bool:
    """Perform basic hostname syntax checks."""

    if len(value) > 253:
        return False

    labels = value.rstrip(".").split(".")

    if len(labels) < 2:
        return False

    return all(
        1 <= len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(char.isalnum() or char == "-" for char in label)
        for label in labels
    )

def _valid_url(value: str) -> bool:
    """Check that a URL has a supported scheme and hostname."""

    try:
        parsed = urlparse(value)
        return (
            parsed.scheme.lower() in {"http", "https", "ftp"}
            and bool(parsed.hostname)
            and _valid_domain(parsed.hostname)
                or parsed.scheme.lower() in {"http", "https", "ftp"}
                and parsed.hostname is not None
                and _is_ip(parsed.hostname)
        )
    except (ValueError, UnicodeError):
        return False

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _add_match(
    matches: list[ArtefactMatch],
    *,
    artefact_type: str,
    confidence: float,
    evidence: str,
    start: int | None = None,
    end: int | None = None,
) -> None:
    """Append a match while avoiding exact duplicates."""

    candidate = ArtefactMatch(
        artefact_type=artefact_type,
        confidence=confidence,
        evidence=evidence,
        start=start,
        end=end,
    )

    if candidate not in matches:
        matches.append(candidate)

def _identify_text(text: str) -> list[ArtefactMatch]:
    """Identify artefact structures in text."""

    matches: list[ArtefactMatch] = []
    stripped = text.strip()

    if not stripped:
        return matches

    # Recognise structured formats before scanning individual identifiers.
    if stripped.startswith(("{", "[")):
        try:
            json.loads(stripped)
            _add_match(
                matches,
                artefact_type="json_data",
                confidence=0.99,
                evidence="Input parses as JSON.",
            )
        except (json.JSONDecodeError, RecursionError):
            pass

    if stripped.startswith("<?xml") or (
        stripped.startswith("<") and stripped.endswith(">")
    ):
        try:
            ET.fromstring(stripped)
            _add_match(
                matches,
                artefact_type="xml_data",
                confidence=0.99,
                evidence="Input parses as XML.",
            )
        except ET.ParseError:
            pass

    if re.search(
        r"(?im)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) "
        r"\S+ HTTP/\d(?:\.\d)?$",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="http_request",
            confidence=0.99,
            evidence="HTTP request-line structure detected.",
        )

    if re.search(
        r"(?im)^HTTP/\d(?:\.\d)?\s+\d{3}\b",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="http_response",
            confidence=0.99,
            evidence="HTTP response status-line structure detected.",
        )

    if re.search(
        r"(?im)^From:\s+.+\n(?:.*\n)*Subject:\s*.+",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="email_message",
            confidence=0.90,
            evidence="Email-like From and Subject headers detected.",
        )

    if re.search(
        r"(?im)^(?:Received|Message-ID|MIME-Version|"
        r"Content-Type|Return-Path):\s*.+$",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="email_headers",
            confidence=0.90,
            evidence="Recognised email header fields detected.",
        )

    if re.search(
        r"(?is)<(?:!doctype\s+html|html)(?:\s|>)",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="html_source",
            confidence=0.99,
            evidence="HTML document structure detected.",
        )

    if re.search(
        r"(?im)^\s*(?:User-agent|Disallow|Allow|Sitemap):",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="robots_txt",
            confidence=0.95,
            evidence="Recognised robots.txt directives detected.",
        )

    if re.search(
        r"(?im)^\s*(?:\$TTL|@?\s+\d+\s+IN\s+"
        r"(?:A|AAAA|CNAME|MX|NS|SOA|TXT|PTR)\b)",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="dns_records",
            confidence=0.85,
            evidence="DNS zone-record structure detected.",
        )

    if re.search(
        r"(?im)^\s*(?:Host|Hostname|Address|"
        r"Netid|Netmask|Broadcast)\s*:",
        stripped,
    ) and re.search(r"(?im)^\s*(?:Address|Netmask)\s*:", stripped):
        _add_match(
            matches,
            artefact_type="network_configuration",
            confidence=0.75,
            evidence="Network configuration fields detected.",
        )

    if re.search(
        r"(?im)^\s*(?:-----BEGIN CERTIFICATE-----|"
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|"
        r"-----BEGIN OPENSSH PRIVATE KEY-----)",
        stripped,
    ):
        _add_match(
            matches,
            artefact_type="cryptographic_key_material",
            confidence=0.99,
            evidence="PEM-style cryptographic material header detected.",
        )

    # Extract identifiers. Keep their source offsets for provenance.
    for artefact_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(".,;:!?)\]}")

            if not value:
                continue

            if artefact_type == "url" and not _valid_url(value):
                continue

            if artefact_type == "domain" and not _valid_domain(value):
                continue

            if artefact_type == "ipv4_address":
                if not _is_ip(value):
                    continue
                artefact_type = "ip_address"

            elif artefact_type == "ipv6_candidate":
                if not _is_ip(value):
                    continue
                artefact_type = "ip_address"

            _add_match(
                matches,
                artefact_type=artefact_type,
                confidence=0.95 if artefact_type in {
                    "email_address",
                    "url",
                    "ip_address",
                    "mac_address",
                    "uuid",
                } else 0.80,
                evidence=value,
                start=match.start(),
                end=match.start() + len(value),
            )

    # CSV is checked last because arbitrary prose can resemble a table.
    if "\n" in stripped and "," in stripped:
        try:
            rows = list(csv.reader(io.StringIO(stripped)))
            if len(rows) >= 2 and rows[0] and all(
                len(row) == len(rows[0]) for row in rows
            ):
                _add_match(
                    matches,
                    artefact_type="csv_data",
                    confidence=0.75,
                    evidence="Consistent comma-separated rows detected.",
                )
        except csv.Error:
            pass

    # JSON Lines: multiple independent JSON objects, one per line.
    if "\n" in stripped:
        lines = [line.strip() for line in stripped.splitlines() if line.strip()]
        if len(lines) >= 2:
            try:
                for line in lines:
                    json.loads(line)
                _add_match(
                    matches,
                    artefact_type="jsonl_data",
                    confidence=0.95,
                    evidence="Every non-empty line parses as JSON.",
                )
            except (json.JSONDecodeError, RecursionError):
                pass

    return matches

def identify(
    input_data: str | bytes,
    *,
    source_hint: str | None = None,
    request_id: str | None = None,
) -> Packet:
    """Identify artefacts and return a universal packet.

    This function does not execute extractors or perform network lookups.
    """

    if not isinstance(input_data, (str, bytes)):
        raise TypeError("input_data must be str or bytes.")

    matches: list[ArtefactMatch] = []
    is_binary = isinstance(input_data, bytes)

    if is_binary:
        for signature, artefact_type in MAGIC_SIGNATURES:
            if input_data.startswith(signature):
                _add_match(
                    matches,
                    artefact_type=artefact_type,
                    confidence=0.99,
                    evidence=f"Recognised file signature: {signature!r}",
                )

        # A ZIP-based Office document is also a ZIP archive. Further
        # container inspection can refine this classification later.
        text = _decode_text(input_data)
    else:
        text = input_data

    if text is not None:
        matches.extend(_identify_text(text))

    # Deduplicate while retaining the first observed occurrence.
    unique_matches: list[ArtefactMatch] = []
    seen: set[tuple[str, str, int | None]] = set()

    for match in matches:
        key = (match.artefact_type, match.evidence, match.start)
        if key not in seen:
            seen.add(key)
            unique_matches.append(match)

    matches = unique_matches

    entities: list[dict[str, Any]] = []
    related_entities: list[dict[str, Any]] = []

    for match in matches:
        if match.artefact_type in {
            "email_address",
            "url",
            "domain",
            "ip_address",
            "mac_address",
            "uuid",
            "jwt_token",
            "timestamp_iso8601",
        }:
            entities.append({
                "type": match.artefact_type,
                "value": match.evidence,
                "source_span": {
                    "start": match.start,
                    "end": match.end,
                },
            })

    # Related entities are not inferred here. The identifier has not
    # established source-record relationships at this stage.
    data = {
        "matches": [match.to_dict() for match in matches],
        "match_count": len(matches),
        "identified_types": sorted({
            match.artefact_type for match in matches
        }),
        "unidentified": not bool(matches),
    }

    packet = Packet(
        request_id=request_id or str(uuid4()),
        stage="identification",
        artefact_type="identification_result",
        input=input_data,
        source={
            "type": source_hint or "user_input",
        },
        status=PacketStatus.SUCCESS,
        data=data,
        entities=entities,
        related_entities=related_entities,
        provenance={
            "source": source_hint or "user_input",
            "method": "local_content_identification",
            "network_accessed": False,
        },
        errors=[],
        metadata={
            "input_kind": "bytes" if is_binary else "text",
            "input_size": len(input_data),
        },
    )

    return packet