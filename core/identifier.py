from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
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
    def identify(self, target: str) -> Entity:
        target = target.strip()

        if not target:
            return Entity(
                value=target,
                type=EntityType.UNKNOWN,
            )

        if self._is_email(target):
            return Entity(
                value=target,
                type=EntityType.EMAIL,
            )

        if self._is_url(target):
            return Entity(
                value=target,
                type=EntityType.URL,
            )

        if self._is_ip(target):
            return Entity(
                value=target,
                type=EntityType.IP_ADDRESS,
            )

        if self._is_phone(target):
            return Entity(
                value=target,
                type=EntityType.PHONE,
            )

        if self._is_domain(target):
            return Entity(
                value=target,
                type=EntityType.DOMAIN,
            )

        if self._is_username(target):
            return Entity(
                value=target,
                type=EntityType.USERNAME,
            )

        if self._looks_like_person(target):
            return Entity(
                value=target,
                type=EntityType.PERSON,
            )

        return Entity(
            value=target,
            type=EntityType.UNKNOWN,
        )

    @staticmethod
    def _is_email(value: str) -> bool:
        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        return bool(re.match(pattern, value))

    @staticmethod
    def _is_url(value: str) -> bool:
        parsed = urlparse(value)

        return parsed.scheme in {"http", "https"} and bool(
            parsed.netloc
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
        digits = re.sub(r"[^\d]", "", value)

        if not digits:
            return False

        return 7 <= len(digits) <= 15

    @staticmethod
    def _is_domain(value: str) -> bool:
        if len(value) > 253:
            return False

        if " " in value:
            return False

        if value.startswith(".") or value.endswith("."):
            return False

        labels = value.rstrip(".").split(".")

        if len(labels) < 2:
            return False

        label_pattern = re.compile(
            r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
            r"[a-zA-Z0-9])?$"
        )

        return all(
            label_pattern.match(label)
            for label in labels
        )

    @staticmethod
    def _is_username(value: str) -> bool:
        if not 1 <= len(value) <= 30:
            return False

        return bool(
            re.fullmatch(
                r"[A-Za-z0-9._-]+",
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