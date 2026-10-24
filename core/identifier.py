from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

class EntityType(Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    EMAIL = "email"
    USERNAME = "username"
    URL = "url"
    NAME = "name"
    PHONE_NUMBER = "phone_number"
    MEDIA = "media"
    DOCUMENT = "document"
    FILE_HASH = "file_hash"
    PACKAGE = "package"
    APPLICATION = "application"
    VULNERABILITY = "vulnerability"
    CRYPTO_WALLET = "crypto_wallet"
    REPORT = "report"
    UNKNOWN = "unknown"

class CommandType(Enum):
    HELP = "help"
    ABOUT = "about"
    CLEAR = "clear"
    HISTORY = "history"
    STATUS = "status"
    QUIT = "quit"

@dataclass(frozen=True)
class Entity:
    value: str
    type: EntityType

@dataclass(frozen=True)
class Command:
    type: CommandType
    argument: str | None = None

class Identifier:
    """Recognize CLI commands and classify investigation targets."""

    COMMAND_ALIASES = {
        "help": CommandType.HELP,
        "about": CommandType.ABOUT,
        "clear": CommandType.CLEAR,
        "history": CommandType.HISTORY,
        "status": CommandType.STATUS,
        "q": CommandType.QUIT,
        "q.": CommandType.QUIT,
        "quit": CommandType.QUIT,
        "quit.": CommandType.QUIT,
        "bye": CommandType.QUIT,
        "bye.": CommandType.QUIT,
        "exit": CommandType.QUIT,
        "exit.": CommandType.QUIT,
    }

    # Explicit prefixes for target types that cannot be reliably
    # distinguished from arbitrary text.
    TYPE_PREFIXES = {
        "ip": EntityType.IP_ADDRESS,
        "ip_address": EntityType.IP_ADDRESS,
        "domain": EntityType.DOMAIN,
        "email": EntityType.EMAIL,
        "username": EntityType.USERNAME,
        "url": EntityType.URL,
        "name": EntityType.NAME,
        "phone": EntityType.PHONE_NUMBER,
        "phone_number": EntityType.PHONE_NUMBER,
        "media": EntityType.MEDIA,
        "image": EntityType.MEDIA,
        "document": EntityType.DOCUMENT,
        "file": EntityType.DOCUMENT,
        "hash": EntityType.FILE_HASH,
        "file_hash": EntityType.FILE_HASH,
        "package": EntityType.PACKAGE,
        "app": EntityType.APPLICATION,
        "application": EntityType.APPLICATION,
        "cve": EntityType.VULNERABILITY,
        "vulnerability": EntityType.VULNERABILITY,
        "wallet": EntityType.CRYPTO_WALLET,
        "crypto_wallet": EntityType.CRYPTO_WALLET,
        "report": EntityType.REPORT,
    }

    # SHA-1, SHA-256, SHA-384 and SHA-512.
    HASH_LENGTHS = {40, 64, 96, 128}

    # Common CVE identifier format.
    CVE_PATTERN = re.compile(
        r"CVE-\d{4}-\d{4,}",
        re.IGNORECASE,
    )

    # Common Ethereum-style address.
    ETHEREUM_PATTERN = re.compile(r"0x[a-fA-F0-9]{40}")

    # Bitcoin legacy addresses and common mainnet/testnet prefixes.
    BITCOIN_PATTERN = re.compile(
        r"(?:"
        r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|"
        r"bc1[a-zA-HJ-NP-Z0-9]{11,71}"
        r"|"
        r"[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|"
        r"tb1[a-zA-HJ-NP-Z0-9]{11,71}"
        r")"
    )

    def identify_command(self, value: str) -> Command | None:
        """Recognize a CLI command without executing it."""

        value = value.strip()

        if not value:
            return None

        parts = value.split(maxsplit=1)
        name = parts[0].casefold()
        argument = parts[1].strip() if len(parts) > 1 else None

        command_type = self.COMMAND_ALIASES.get(name)

        if command_type is None:
            return None

        return Command(
            type=command_type,
            argument=argument or None,
        )

    def identify(self, target: str) -> Entity:
        """Classify a target without running tools or normalizing it."""

        target = target.strip()

        if not target:
            return Entity(target, EntityType.UNKNOWN)

        # Explicit prefixes take priority, allowing ambiguous targets
        # to be classified without guessing.
        prefixed = self._identify_prefixed_target(target)
        if prefixed is not None:
            return prefixed

        if self._is_email(target):
            return Entity(target, EntityType.EMAIL)

        if self._is_url(target):
            return Entity(target, EntityType.URL)

        if self._is_ip(target):
            return Entity(target, EntityType.IP_ADDRESS)

        if self._is_file_hash(target):
            return Entity(target, EntityType.FILE_HASH)

        if self._is_vulnerability(target):
            return Entity(target, EntityType.VULNERABILITY)

        if self._is_crypto_wallet(target):
            return Entity(target, EntityType.CRYPTO_WALLET)

        if self._is_phone_number(target):
            return Entity(target, EntityType.PHONE_NUMBER)

        if self._is_domain(target):
            return Entity(target, EntityType.DOMAIN)

        # A plain string is not enough to distinguish a username,
        # package, application, person, or organization reliably.
        return Entity(target, EntityType.UNKNOWN)

    def _identify_prefixed_target(self, target: str) -> Entity | None:
        """Identify targets written as 'type:value'."""

        if ":" not in target:
            return None

        prefix, value = target.split(":", maxsplit=1)
        entity_type = self.TYPE_PREFIXES.get(prefix.casefold())

        if entity_type is None or not value.strip():
            return None

        # The report entity represents a request to build a report,
        # not a standalone collector.
        return Entity(value.strip(), entity_type)

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
        try:
            parsed = urlparse(value)

            return (
                parsed.scheme.casefold() in {"http", "https"}
                and bool(parsed.hostname)
                and not any(char.isspace() for char in value)
            )
        except ValueError:
            return False

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @classmethod
    def _is_file_hash(cls, value: str) -> bool:
        return (
            len(value) in cls.HASH_LENGTHS
            and bool(re.fullmatch(r"[a-fA-F0-9]+", value))
        )

    @classmethod
    def _is_vulnerability(cls, value: str) -> bool:
        return bool(cls.CVE_PATTERN.fullmatch(value))

    @classmethod
    def _is_crypto_wallet(cls, value: str) -> bool:
        return bool(
            cls.ETHEREUM_PATTERN.fullmatch(value)
            or cls.BITCOIN_PATTERN.fullmatch(value)
        )

    @staticmethod
    def _is_phone_number(value: str) -> bool:
        # Accept common phone formatting, not arbitrary text with digits.
        if not re.fullmatch(r"[+0-9().\s-]+", value):
            return False

        digits = re.sub(r"\D", "", value)
        return 7 <= len(digits) <= 15

    @staticmethod
    def _is_domain(value: str) -> bool:
        if len(value) > 253 or any(char.isspace() for char in value):
            return False

        candidate = value.rstrip(".")

        if not candidate or "." not in candidate:
            return False

        try:
            ascii_domain = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            return False

        if len(ascii_domain) > 253:
            return False

        labels = ascii_domain.split(".")

        if len(labels) < 2:
            return False

        label_pattern = re.compile(
            r"^[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
        )

        return all(
            label_pattern.fullmatch(label)
            for label in labels
        )

if __name__ == "__main__":
    identifier = Identifier()

    print("Theseus Identifier Test")
    print("Enter a target or type 'q' to quit.\n")
    print("Use prefixes for ambiguous targets, e.g. package:requests")
    print("Use report:target to request a report.\n")

    while True:
        try:
            target = input("target> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        command = identifier.identify_command(target)

        if command is not None:
            if command.type == CommandType.QUIT:
                break

            print(f"Command: {command.type.value}")
            if command.argument:
                print(f"Argument: {command.argument}")
            continue

        entity = identifier.identify(target)
        print(f"Type:  {entity.type.value}")
        print(f"Value: {entity.value}\n")