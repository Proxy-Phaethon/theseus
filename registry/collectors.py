"""
Theseus collector registry.

Maps investigation entity types to their normalizers and collectors.
Execution and result handling belong to the orchestration layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.identifier import EntityType

class CollectorStatus(Enum):
    IMPLEMENTED = "implemented"
    NOT_IMPLEMENTED = "not_implemented"

@dataclass(frozen=True)
class ComponentSpec:
    """Describes one importable investigation component."""

    name: str
    module: str
    function: str
    description: str = ""
    stage: str = "collector"
    observation_mode: str = "mapping"

@dataclass(frozen=True)
class EntityCollectorSpec:
    """Describes the investigation pipeline for one entity type."""

    entity_type: EntityType
    normalizer: ComponentSpec | None
    collectors: tuple[ComponentSpec, ...] = ()

    @property
    def status(self) -> CollectorStatus:
        if self.normalizer is None or not self.collectors:
            return CollectorStatus.NOT_IMPLEMENTED

        return CollectorStatus.IMPLEMENTED

def _component(
    name: str,
    module: str,
    function: str,
    description: str = "",
    *,
    stage: str = "collector",
    observation_mode: str = "mapping",
) -> ComponentSpec:
    """Create a registry component with its execution-stage metadata."""
    return ComponentSpec(
        name=name,
        module=module,
        function=function,
        description=description,
        stage=stage,
        observation_mode=observation_mode,
    )

ENTITY_COLLECTORS: dict[EntityType, EntityCollectorSpec] = {
    EntityType.IP_ADDRESS: EntityCollectorSpec(
        entity_type=EntityType.IP_ADDRESS,
        normalizer=_component(
            "IP classification and normalization",
            "tools.ip.classification",
            "run",
            "Validates, canonicalizes, and classifies an IPv4 or IPv6 address.",
        ),
        collectors=(
            _component(
                "IP classification",
                "tools.ip.classification",
                "run",
                "Classifies the target IP address.",
            ),
            _component(
                "RDAP lookup",
                "tools.ip.rdap",
                "run",
                "Retrieves IP allocation and registration information.",
            ),
            _component(
                "ASN lookup",
                "tools.ip.asn",
                "run",
                "Identifies the announced ASN and network prefix.",
            ),
            _component(
                "BGP intelligence",
                "tools.ip.bgp",
                "run",
                "Collects routing and BGP observations.",
            ),
            _component(
                "Geolocation",
                "tools.ip.geolocation",
                "run",
                "Retrieves estimated IP geolocation and network details.",
            ),
            _component(
                "Reverse DNS",
                "tools.ip.reverse_dns",
                "run",
                "Looks up PTR records for the target IP.",
            ),
            _component(
                "Port scanner",
                "tools.ip.ports",
                "run",
                "Checks common TCP ports.",
            ),
            _component(
                "Service detection",
                "tools.ip.services",
                "run",
                "Identifies services through protocol probes.",
            ),
            _component(
                "TLS intelligence",
                "tools.ip.tls",
                "run",
                "Inspects TLS certificates and negotiated parameters.",
            ),
            _component(
                "HTTP intelligence",
                "tools.ip.http",
                "run",
                "Inspects HTTP responses and security-related headers.",
            ),
            _component(
                "Hosting classification",
                "tools.ip.hosting",
                "run",
                "Checks hosting, VPN, Tor, and mobile classifications.",
            ),
            _component(
                "IP reputation",
                "tools.ip.reputation",
                "run",
                "Retrieves public IP reputation indicators.",
            ),
            _component(
                "Threat intelligence",
                "tools.ip.threat_intel",
                "run",
                "Checks public threat-intelligence feeds.",
            ),
            _component(
                "Passive DNS",
                "tools.ip.passive_dns",
                "run",
                "Retrieves historical DNS observations.",
            ),
            _component(
                "Mail infrastructure",
                "tools.ip.mail",
                "run",
                "Inspects SMTP responses and advertised capabilities.",
            ),
            _component(
                "Vulnerability intelligence",
                "tools.ip.vulnerabilities",
                "run",
                "Checks available product evidence against vulnerability sources.",
                stage="analysis",
                observation_mode="list",
            ),
            _component(
                "Historical intelligence",
                "tools.ip.history",
                "run",
                "Collects public routing and certificate history.",
            ),
            _component(
                "Relationship analysis",
                "tools.ip.relationships",
                "run",
                "Builds an evidence-based relationship graph.",
                stage="analysis",
                observation_mode="mapping",
            ),
            _component(
                "Reachability",
                "tools.ip.reachability",
                "run",
                "Checks ICMP and TCP responsiveness.",
            ),
            _component(
                "Context aggregation",
                "tools.ip.context",
                "run",
                "Aggregates contextual observations from other collectors.",
                stage="analysis",
                observation_mode="mapping",
            ),
        ),
    ),

    EntityType.DOMAIN: EntityCollectorSpec(
        entity_type=EntityType.DOMAIN,
        normalizer=None,
    ),

    EntityType.EMAIL: EntityCollectorSpec(
        entity_type=EntityType.EMAIL,
        normalizer=_component(
            "Email normalizer",
            "tools.email.normalize",
            "normalize_email",
            "Normalizes an email address before investigation.",
        ),
        collectors=(
            _component(
                "Email syntax",
                "tools.email.syntax",
                "validate_email_syntax",
                "Validates email address syntax.",
            ),
            _component(
                "Email domain analysis",
                "tools.email.domain",
                "analyze_email_domain",
                "Extracts and analyzes the email domain.",
            ),
            _component(
                "MX lookup",
                "tools.email.mx",
                "lookup_mx",
                "Checks mail exchange records and mail acceptance.",
            ),
            _component(
                "Email security",
                "tools.email.email_security",
                "collect_email_security",
                "Checks email-domain security policies.",
            ),
            _component(
                "Breach lookup",
                "tools.email.breach",
                "lookup_breaches",
                "Checks the configured breach intelligence source.",
            ),
            _component(
                "Service discovery",
                "tools.email.services",
                "discover_services",
                "Checks registered email-associated services.",
            ),
        ),
    ),

    EntityType.USERNAME: EntityCollectorSpec(
        entity_type=EntityType.USERNAME,
        normalizer=None,
    ),

    EntityType.URL: EntityCollectorSpec(
        entity_type=EntityType.URL,
        normalizer=None,
    ),

    EntityType.NAME: EntityCollectorSpec(
        entity_type=EntityType.NAME,
        normalizer=None,
    ),

    EntityType.PHONE_NUMBER: EntityCollectorSpec(
        entity_type=EntityType.PHONE_NUMBER,
        normalizer=None,
    ),

    EntityType.MEDIA: EntityCollectorSpec(
        entity_type=EntityType.MEDIA,
        normalizer=None,
    ),

    EntityType.DOCUMENT: EntityCollectorSpec(
        entity_type=EntityType.DOCUMENT,
        normalizer=None,
    ),

    EntityType.FILE_HASH: EntityCollectorSpec(
        entity_type=EntityType.FILE_HASH,
        normalizer=None,
    ),

    EntityType.PACKAGE: EntityCollectorSpec(
        entity_type=EntityType.PACKAGE,
        normalizer=None,
    ),

    EntityType.APPLICATION: EntityCollectorSpec(
        entity_type=EntityType.APPLICATION,
        normalizer=None,
    ),

    EntityType.VULNERABILITY: EntityCollectorSpec(
        entity_type=EntityType.VULNERABILITY,
        normalizer=None,
    ),

    EntityType.CRYPTO_WALLET: EntityCollectorSpec(
        entity_type=EntityType.CRYPTO_WALLET,
        normalizer=None,
    ),

    EntityType.REPORT: EntityCollectorSpec(
        entity_type=EntityType.REPORT,
        normalizer=None,
    ),

    EntityType.UNKNOWN: EntityCollectorSpec(
        entity_type=EntityType.UNKNOWN,
        normalizer=None,
    ),
}

def get_entity_spec(
    entity_type: EntityType,
) -> EntityCollectorSpec:
    """Return the registered investigation specification."""
    return ENTITY_COLLECTORS.get(
        entity_type,
        EntityCollectorSpec(
            entity_type=entity_type,
            normalizer=None,
        ),
    )

def get_collectors(
    entity_type: EntityType,
) -> tuple[ComponentSpec, ...]:
    """Return the collector components registered for an entity."""
    return get_entity_spec(entity_type).collectors

def get_normalizer(
    entity_type: EntityType,
) -> ComponentSpec | None:
    """Return the normalizer registered for an entity."""
    return get_entity_spec(entity_type).normalizer

def get_status(
    entity_type: EntityType,
) -> CollectorStatus:
    """Return whether an entity currently has a registered pipeline."""
    return get_entity_spec(entity_type).status

def list_entities() -> list[dict[str, Any]]:
    """Return a summary of registered entity pipelines."""
    return [
        {
            "entity_type": entity_type.value,
            "status": get_status(entity_type).value,
            "normalizer": (
                get_normalizer(entity_type).name
                if get_normalizer(entity_type)
                else None
            ),
            "collectors": [
                collector.name
                for collector in get_collectors(entity_type)
            ],
        }
        for entity_type in EntityType
    ]

if __name__ == "__main__":
    for entry in list_entities():
        print(f"\n{entry['entity_type']}: {entry['status']}")

        if entry["normalizer"]:
            print(f"  Normalizer: {entry['normalizer']}")

        if entry["collectors"]:
            for collector in entry["collectors"]:
                print(f"  Collector:  {collector}")