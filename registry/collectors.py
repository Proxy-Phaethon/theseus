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
) -> ComponentSpec:
    return ComponentSpec(
        name=name,
        module=module,
        function=function,
        description=description,
    )

# Each entity type has an explicit entry, including types whose
# investigation pipelines have not been implemented yet.
ENTITY_COLLECTORS: dict[EntityType, EntityCollectorSpec] = {
    EntityType.IP_ADDRESS: EntityCollectorSpec(
        entity_type=EntityType.IP_ADDRESS,
        normalizer=None,
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