from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum

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
    """
    Identifies the type of an investigation target.
    """

    def identify(self, target: str) -> Entity:
        target = target.strip()

        if not target:
            return Entity(
                value=target,
                type=EntityType.UNKNOWN,
            )

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

        if self._is_username(target):
            return Entity(target, EntityType.USERNAME)

        if self._looks_like_person(target):
            return Entity(target, EntityType.PERSON)

        return Entity(target, EntityType.UNKNOWN)

    @staticmethod
    def _is_email(value: str) -> bool:
        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        return bool(re.match(pattern, value))

    @staticmethod
    def _is_url(value: str) -> bool:
        pattern = r"^https?://[^\s]+$"
        return bool(re.match(pattern, value, re.IGNORECASE))

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
        pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        )

        return bool(re.match(pattern, value))

    @staticmethod
    def _is_username(value: str) -> bool:
        pattern = r"^[a-zA-Z0-9_.-]{2,32}$"

        return bool(re.match(pattern, value))

    @staticmethod
    def _looks_like_person(value: str) -> bool:
        parts = value.split()

        return len(parts) >= 2 and all(
            part.replace("-", "").isalpha()
            for part in parts
        )