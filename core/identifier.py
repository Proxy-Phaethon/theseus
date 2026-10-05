from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

class EntityType(Enum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    PHONE = "phone"
    PERSON = "person"
    ORGANIZATION = "organization"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class Entity:
    value: str
    type: EntityType

class Identifier:
    def __init__(
        self,
        tools: dict[EntityType, list[Any]] | None = None,
    ) -> None:
        self.tools = tools or {}

    def identify(self, target: str) -> Entity:
        target = target.strip()

        if not target:
            return Entity(target, EntityType.UNKNOWN)

        if self._is_email(target):
            return Entity(target, EntityType.EMAIL)

        if self._is_url(target):
            return Entity(target, EntityType.URL)

        if self._is_ip(target):
            return Entity(target, EntityType.IP_ADDRESS)

        if self._is_phone(target):
            return Entity(target, EntityType.PHONE)

        if self._is_domain(target):
            return Entity(target, EntityType.DOMAIN)

        username = target.lstrip("@")

        if self._is_username(username):
            return Entity(username, EntityType.USERNAME)

        if self._looks_like_person(target):
            return Entity(target, EntityType.PERSON)

        return Entity(target, EntityType.UNKNOWN)

    def run(self, entity: Entity) -> list[tuple[str, Any]]:
        tools = self.tools.get(entity.type, [])

        if not tools:
            raise ValueError(
                f"No tools available for {entity.type.value}"
            )

        results = []

        for tool in tools:
            try:
                result = tool.run(entity.value)
                results.append((tool.__class__.__name__, result))
            except Exception as exc:
                print(
                    f"[!] {tool.__class__.__name__} failed: {exc}"
                )

        return results

    def process(
        self,
        target: str,
    ) -> tuple[Entity, list[tuple[str, Any]]]:
        entity = self.identify(target)
        results = self.run(entity)

        return entity, results

    @staticmethod
    def _is_email(value: str) -> bool:
        return bool(
            re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                value,
            )
        )

    @staticmethod
    def _is_url(value: str) -> bool:
        parsed = urlparse(value)

        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
        )

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_phone(value: str) -> bool:
        digits = re.sub(r"\D", "", value)

        return 7 <= len(digits) <= 15

    @staticmethod
    def _is_domain(value: str) -> bool:
        if len(value) > 253 or " " in value:
            return False

        labels = value.rstrip(".").split(".")

        if len(labels) < 2:
            return False

        pattern = re.compile(
            r"^[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
        )

        return all(pattern.fullmatch(label) for label in labels)

    @staticmethod
    def _is_username(value: str) -> bool:
        return bool(
            re.fullmatch(
                r"[A-Za-z0-9._-]{1,30}",
                value,
            )
        )

    @staticmethod
    def _looks_like_person(value: str) -> bool:
        parts = value.split()

        if len(parts) < 2:
            return False

        return all(
            re.fullmatch(r"[A-Za-z][A-Za-z'-]*", part)
            for part in parts
        )