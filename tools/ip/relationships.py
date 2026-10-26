"""Build an evidence-based relationship graph from IP collector results.

This module does not perform network requests. It consumes observations
from existing collectors and converts supported relationships into nodes
and edges for the Theseus responder.

No API keys or third-party Python packages are required.

Important:
- Shared infrastructure does not prove common ownership.
- Certificate names do not prove that a domain currently resolves to an IP.
- Network allocation does not necessarily identify the operator of a service.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

MAX_NODES = 500
MAX_EDGES = 1000

DOMAIN_PATTERN = re.compile(
    r"(?i)^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\.?$"
)

ASN_PATTERN = re.compile(r"(?i)^(?:AS)?(\d{1,10})$")

def _clean(value: Any) -> str | None:
    """Return a normalized, non-empty string."""
    if value is None:
        return None

    value = str(value).strip()

    if not value or value.lower() in {
        "none",
        "null",
        "unknown",
        "n/a",
        "not available",
    }:
        return None

    return value

def _canonical_ip(value: Any) -> str | None:
    value = _clean(value)
    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None

def _canonical_prefix(value: Any) -> str | None:
    value = _clean(value)
    if not value:
        return None

    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None

def _canonical_asn(value: Any) -> str | None:
    value = _clean(value)
    if not value:
        return None

    match = ASN_PATTERN.fullmatch(value)
    if not match:
        return None

    number = int(match.group(1))
    if number > 4294967295:
        return None

    return f"AS{number}"

def _canonical_domain(value: Any) -> str | None:
    value = _clean(value)
    if not value:
        return None

    value = value.rstrip(".").lower()

    # Reverse-DNS query names are not ordinary hostnames/domains.
    if value.endswith((".in-addr.arpa", ".ip6.arpa")):
        return None

    # Do not treat URLs, email addresses, or arbitrary text as domains.
    if "://" in value or "/" in value or "@" in value:
        return None

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not DOMAIN_PATTERN.fullmatch(value):
        return None

    return value

def _node_id(node_type: str, value: str) -> str:
    """Generate a stable, compact node ID."""
    raw = f"{node_type}:{value}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return f"{node_type}:{digest}"

def _make_node(
    node_type: str,
    value: str,
    *,
    label: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": _node_id(node_type, value),
        "type": node_type,
        "value": value,
        "label": label or value,
        "attributes": attributes or {},
    }

def _source_name(module_name: str, result: Any) -> str:
    if isinstance(result, dict):
        sources = result.get("sources")

        if isinstance(sources, dict):
            return module_name

        return _clean(result.get("source")) or module_name

    return module_name

def _observation(
    *,
    source: str,
    relation: str,
    evidence: Any = None,
    observed_at: Any = None,
    confidence: str = "observed",
) -> dict[str, Any]:
    return {
        "source": source,
        "relation": relation,
        "evidence": evidence,
        "observed_at": _clean(observed_at),
        "confidence": confidence,
    }

def run(
    target: str,
    observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract supported relationships from existing collector outputs.

    Args:
        target: The investigated IP address.
        observations: Mapping of module names to their raw results.
            Example:
                {
                    "rdap": {...},
                    "asn": {...},
                    "bgp": {...},
                    "reverse_dns": {...},
                    "tls": {...},
                    "passive_dns": {...},
                    "hosting": {...},
                    "threat_intel": {...},
                }

    Returns:
        A graph-like structure containing nodes, edges, and limitations.
    """
    canonical_target = _canonical_ip(target)

    if not canonical_target:
        return {
            "status": "error",
            "target": str(target),
            "error": "Invalid IP address",
            "nodes": [],
            "edges": [],
        }

    observations = observations or {}

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    truncated = {
        "nodes": False,
        "edges": False,
    }

    def add_node(
        node_type: str,
        value: Any,
        *,
        label: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> str | None:
        value = _clean(value)
        if not value:
            return None

        node = _make_node(
            node_type,
            value,
            label=label,
            attributes=attributes,
        )

        node_id = node["id"]

        if node_id not in nodes and len(nodes) >= MAX_NODES:
            truncated["nodes"] = True
            return None

        if node_id not in nodes:
            nodes[node_id] = node
        elif attributes:
            nodes[node_id]["attributes"].update(attributes)

        return node_id

    def add_edge(
        source_id: str | None,
        target_id: str | None,
        relation: str,
        evidence: dict[str, Any],
    ) -> None:
        if not source_id or not target_id or source_id == target_id:
            return

        key = (source_id, target_id, relation)

        if key not in edges:
            if len(edges) >= MAX_EDGES:
                truncated["edges"] = True
                return

            edges[key] = {
                "source": source_id,
                "target": target_id,
                "relation": relation,
                "evidence": [],
            }

        if evidence not in edges[key]["evidence"]:
            edges[key]["evidence"].append(evidence)

    ip_id = add_node("ip", canonical_target)
    if not ip_id:
        return {
            "status": "error",
            "target": canonical_target,
            "error": "Could not create target node",
            "nodes": [],
            "edges": [],
        }

    # Extract fields only from a successful module result.
    def module_data(name: str) -> dict[str, Any]:
        result = observations.get(name)

        if not isinstance(result, dict):
            return {}

        if result.get("status") not in {"success", "partial"}:
            return {}

        return result

    def link_value(
        node_type: str,
        value: Any,
        relation: str,
        module_name: str,
        *,
        label: str | None = None,
        evidence_value: Any = None,
        observed_at: Any = None,
    ) -> None:
        if node_type == "domain":
            normalized = _canonical_domain(value)
        elif node_type == "ip":
            normalized = _canonical_ip(value)
        elif node_type == "network":
            normalized = _canonical_prefix(value)
        elif node_type == "asn":
            normalized = _canonical_asn(value)
        else:
            normalized = _clean(value)

        if not normalized:
            return

        node_id = add_node(node_type, normalized, label=label)
        add_edge(
            ip_id,
            node_id,
            relation,
            _observation(
                source=module_name,
                relation=relation,
                evidence=evidence_value,
                observed_at=observed_at,
            ),
        )

    # RDAP: allocation and registration relationships.
    rdap = module_data("rdap")
    rdap_source = _source_name("rdap", rdap)

    for key in ("cidr", "network", "prefix"):
        value = rdap.get(key)

        if isinstance(value, list):
            for item in value:
                link_value(
                    "network",
                    item,
                    "within_registered_network",
                    rdap_source,
                    evidence_value={key: item},
                )
        elif isinstance(value, str):
            link_value(
                "network",
                value,
                "within_registered_network",
                rdap_source,
                evidence_value={key: value},
            )

    for key in ("name", "handle", "organization", "org"):
        value = rdap.get(key)
        if not isinstance(value, str):
            continue

        link_value(
            "organization",
            value,
            "registration_record_names",
            rdap_source,
            evidence_value={key: value},
        )

    # ASN origin and network routing observations.
    asn_data = module_data("asn")
    asn_value = (
        asn_data.get("asn")
        or asn_data.get("origin_asn")
        or asn_data.get("origin")
    )

    link_value(
        "asn",
        asn_value,
        "origin_asn_reported",
        _source_name("asn", asn_data),
        evidence_value=asn_data.get("prefix"),
    )

    bgp = module_data("bgp")
    bgp_source = _source_name("bgp", bgp)

    bgp_prefix = bgp.get("prefix")
    link_value(
        "network",
        bgp_prefix,
        "prefix_observed_in_routing",
        bgp_source,
        evidence_value=bgp_prefix,
    )

    origin_asn = (
        bgp.get("origin_asn")
        or bgp.get("asn")
    )

    link_value(
        "asn",
        origin_asn,
        "origin_asn_observed",
        bgp_source,
        evidence_value=origin_asn,
    )

    # Reverse DNS: hostname associated with the IP by a PTR lookup.
    reverse_dns = module_data("reverse_dns")
    rdns_source = _source_name("reverse_dns", reverse_dns)

    hostnames = (
        reverse_dns.get("hostnames")
        or reverse_dns.get("hostnames_found")
        or reverse_dns.get("ptr_records")
        or []
    )

    if isinstance(hostnames, str):
        hostnames = [hostnames]

    if isinstance(hostnames, list):
        for hostname in hostnames:
            if isinstance(hostname, dict):
                hostname = (
                    hostname.get("hostname")
                    or hostname.get("name")
                    or hostname.get("value")
                )

            link_value(
                "domain",
                hostname,
                "reverse_dns_name",
                rdns_source,
                evidence_value={"hostname": hostname},
            )

    # Passive DNS: only create a link when the record explicitly relates
    # the investigated IP to a domain or hostname.
    passive_dns = module_data("passive_dns")
    pdns_source = _source_name("passive_dns", passive_dns)

    pdns_records = passive_dns.get("records", [])

    if isinstance(pdns_records, list):
        for record in pdns_records:
            if not isinstance(record, dict):
                continue

            query_name = (
                record.get("query")
                or record.get("name")
                or record.get("hostname")
            )
            answer = record.get("answer") or record.get("value")
            record_type = str(
                record.get("rrtype")
                or record.get("type")
                or ""
            ).upper()

            # An A/AAAA record is relevant only when its answer matches
            # the investigated IP.
            answer_ip = _canonical_ip(answer)

            if (
                record_type in {"A", "AAAA"}
                and answer_ip == canonical_target
            ):
                link_value(
                    "domain",
                    query_name,
                    "historical_dns_answer",
                    pdns_source,
                    evidence_value=record,
                    observed_at=(
                        record.get("lastSeenTimestamp")
                        or record.get("last_seen")
                    ),
                )

            # A PTR record can associate an IP reverse name with a
            # hostname, but does not prove that hostname resolves back.
            if record_type == "PTR":
                reverse_name = _clean(query_name)
                if reverse_name and reverse_name.lower().endswith(
                    (".in-addr.arpa", ".ip6.arpa")
                ):
                    link_value(
                        "domain",
                        answer,
                        "historical_ptr_answer",
                        pdns_source,
                        evidence_value=record,
                        observed_at=(
                            record.get("lastSeenTimestamp")
                            or record.get("last_seen")
                        ),
                    )

    # TLS: certificate names are connected as certificate-associated
    # names, not as confirmed current DNS resolutions.
    tls = module_data("tls")
    tls_source = _source_name("tls", tls)

    certificates = tls.get("certificates", [])
    if isinstance(certificates, dict):
        certificates = [certificates]
    if not isinstance(certificates, list):
        certificates = []

    # The TLS collector wraps each certificate's X.509 details in
    # item["certificate"]. Accept both that schema and the older flat form.
    for certificate_record in certificates:
        if not isinstance(certificate_record, dict):
            continue

        certificate = certificate_record.get("certificate")
        if not isinstance(certificate, dict):
            certificate = certificate_record

        fingerprints = certificate.get("fingerprints")
        if not isinstance(fingerprints, dict):
            fingerprints = {}

        fingerprint = (
            fingerprints.get("sha256")
            or certificate.get("fingerprint_sha256")
            or certificate.get("sha256_fingerprint")
            or certificate.get("sha256")
        )
        port = certificate_record.get("port", certificate.get("port"))
        service_guess = certificate_record.get(
            "service_guess", certificate.get("service_guess")
        )

        validity = certificate.get("validity")
        if not isinstance(validity, dict):
            validity = {}

        if fingerprint:
            fingerprint_value = str(fingerprint).lower()
            certificate_id = add_node(
                "certificate",
                fingerprint_value,
                label="SHA-256 " + fingerprint_value[:20],
                attributes={
                    "issuer": certificate.get("issuer"),
                    "subject": certificate.get("subject"),
                    "not_before": validity.get("not_before")
                    or certificate.get("not_before"),
                    "not_after": validity.get("not_after")
                    or certificate.get("not_after"),
                    "validity_status": validity.get("status"),
                    "port": port,
                    "service_guess": service_guess,
                },
            )

            add_edge(
                ip_id,
                certificate_id,
                "tls_certificate_observed",
                _observation(
                    source=tls_source,
                    relation="tls_certificate_observed",
                    evidence={
                        "fingerprint_sha256": fingerprint_value,
                        "port": port,
                        "service_guess": service_guess,
                        "certificate_verification": certificate_record.get(
                            "certificate_verification"
                        ),
                    },
                    observed_at=tls.get("timestamp"),
                ),
            )

        # The TLS collector groups SANs by type, e.g. dns_names and
        # ip_addresses. Continue to accept older flat SAN lists as well.
        san_data = (
            certificate.get("subject_alt_names")
            or certificate.get("san")
            or []
        )
        if isinstance(san_data, dict):
            sans = list(san_data.get("dns_names") or [])
        elif isinstance(san_data, str):
            sans = [san_data]
        elif isinstance(san_data, list):
            sans = san_data
        else:
            sans = []

        for name in sans:
            if isinstance(name, dict):
                name = name.get("value") or name.get("name")

            link_value(
                "domain",
                name,
                "certificate_name",
                tls_source,
                evidence_value={
                    "certificate_fingerprint": fingerprint,
                    "port": port,
                    "san": name,
                    "validity": validity,
                },
                observed_at=validity.get("not_after") or tls.get("timestamp"),
            )

    # Hosting classification: provider/organization is a reported
    # classification, not proof of ownership or physical location.
    hosting = module_data("hosting")
    hosting_source = _source_name("hosting", hosting)

    for key in ("organization", "org", "isp", "provider"):
        value = hosting.get(key)
        if isinstance(value, str):
            link_value(
                "organization",
                value,
                "hosting_source_identifies",
                hosting_source,
                evidence_value={key: value},
            )

    # Threat intelligence: preserve indicator provenance and distinguish
    # a source match from a general reputation score.
    threat = module_data("threat_intel")
    threat_source = _source_name("threat_intel", threat)

    threat_records = (
        threat.get("matches")
        or threat.get("indicators")
        or threat.get("records")
        or []
    )

    if isinstance(threat_records, list):
        for record in threat_records:
            if isinstance(record, dict):
                indicator = (
                    record.get("indicator")
                    or record.get("family")
                    or record.get("malware")
                    or record.get("name")
                )
                source = record.get("source") or threat_source
                evidence_value = record
            else:
                indicator = record
                source = threat_source
                evidence_value = record

            link_value(
                "threat_indicator",
                indicator,
                "threat_source_associates",
                str(source),
                evidence_value=evidence_value,
            )

    # Reputation feeds may return named classifications. Keep them
    # separate from confirmed threat-intelligence matches.
    reputation = module_data("reputation")
    reputation_source = _source_name("reputation", reputation)

    for key in ("category", "classification", "risk", "recommendation"):
        value = reputation.get(key)
        if isinstance(value, str):
            link_value(
                "reputation_label",
                value,
                "reputation_source_labels",
                reputation_source,
                evidence_value={key: value},
            )

    successful_modules = [
        name
        for name, result in observations.items()
        if isinstance(result, dict)
        and result.get("status") in {"success", "partial"}
    ]

    if edges and successful_modules:
        status = "success"
    elif successful_modules:
        status = "success"
    else:
        status = "empty"

    return {
        "status": status,
        "target": canonical_target,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "sources_used": sorted(successful_modules),
            "truncated": truncated,
        },
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "limitations": [
            "Relationships are limited to evidence supplied by existing collectors.",
            "A shared ASN, organization label, or certificate name does not prove common ownership.",
            "A historical DNS record does not establish current resolution.",
            "Certificate names do not prove that the named domains resolve to this IP.",
            "Source-specific timestamps and coverage may differ.",
            "Missing observations are not evidence that a relationship does not exist.",
        ],
    }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Build an IP relationship graph from collector JSON"
    )
    parser.add_argument("target", help="IPv4 or IPv6 address")
    parser.add_argument(
        "--input",
        help="Path to JSON containing a mapping of module names to results",
    )
    args = parser.parse_args()

    input_observations = {}
    if args.input:
        with open(args.input, "r", encoding="utf-8") as handle:
            input_observations = json.load(handle)

    print(
        json.dumps(
            run(args.target, input_observations),
            indent=2,
        )
    )