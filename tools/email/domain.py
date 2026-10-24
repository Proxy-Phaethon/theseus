"""
Email domain analysis for Theseus.

Extracts domain metadata from an email address.
Does not perform DNS lookups or verify mailbox existence.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any

from publicsuffix2 import PublicSuffixList

@dataclass
class EmailDomainResult:
    address: str
    domain: str | None
    domain_ascii: str | None
    domain_unicode: str | None
    public_suffix: str | None
    registrable_domain: str | None
    is_ip_literal: bool
    ip_version: int | None
    is_localhost: bool
    is_special_use: bool
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

_PSL = PublicSuffixList()

SPECIAL_USE_DOMAINS = {
    "example",
    "example.com",
    "example.net",
    "example.org",
    "invalid",
    "localhost",
    "test",
}

def _extract_domain(address: str) -> str | None:
    """Extract the domain, respecting quoted local parts."""
    quoted = False
    escaped = False
    separators: list[int] = []

    for index, char in enumerate(address):
        if escaped:
            escaped = False
            continue

        if char == "\\" and quoted:
            escaped = True
            continue

        if char == '"':
            quoted = not quoted
        elif char == "@" and not quoted:
            separators.append(index)

    if quoted or len(separators) != 1:
        return None

    return address[separators[0] + 1:]

def analyze_email_domain(address: str) -> EmailDomainResult:
    original = address if isinstance(address, str) else str(address)
    errors: list[str] = []

    domain = _extract_domain(original)

    if not domain:
        errors.append("Could not extract a domain from the address")
        return EmailDomainResult(
            address=original,
            domain=None,
            domain_ascii=None,
            domain_unicode=None,
            public_suffix=None,
            registrable_domain=None,
            is_ip_literal=False,
            ip_version=None,
            is_localhost=False,
            is_special_use=False,
            errors=errors,
        )

    domain_unicode = unicodedata.normalize("NFC", domain).lower()

    if domain_unicode.endswith("."):
        domain_unicode = domain_unicode[:-1]

    ip_candidate = domain_unicode.strip("[]")
    if ip_candidate.lower().startswith("ipv6:"):
        ip_candidate = ip_candidate[5:]

    try:
        parsed_ip = ipaddress.ip_address(ip_candidate)
        ip_literal = True
        ip_version = parsed_ip.version
        domain_ascii = str(parsed_ip)
    except ValueError:
        ip_literal = False
        ip_version = None

        try:
            domain_ascii = domain_unicode.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            errors.append("Domain could not be converted to IDNA/Punycode")
            return EmailDomainResult(
                address=original,
                domain=domain,
                domain_ascii=None,
                domain_unicode=domain_unicode,
                public_suffix=None,
                registrable_domain=None,
                is_ip_literal=False,
                ip_version=None,
                is_localhost=False,
                is_special_use=False,
                errors=errors,
            )

    is_localhost = domain_ascii == "localhost" or domain_ascii.endswith(
        ".localhost"
    )

    is_special_use = (
        domain_ascii in SPECIAL_USE_DOMAINS
        or is_localhost
        or domain_ascii.endswith(".invalid")
        or domain_ascii.endswith(".test")
        or domain_ascii.endswith(".example")
    )

    public_suffix = None
    registrable_domain = None

    if not ip_literal:
        public_suffix = _PSL.get_tld(domain_ascii)
        registrable_domain = _PSL.get_sld(domain_ascii)

        if public_suffix is None:
            errors.append("Could not determine the public suffix")

    return EmailDomainResult(
        address=original,
        domain=domain,
        domain_ascii=domain_ascii,
        domain_unicode=domain_unicode,
        public_suffix=public_suffix,
        registrable_domain=registrable_domain,
        is_ip_literal=ip_literal,
        ip_version=ip_version,
        is_localhost=is_localhost,
        is_special_use=is_special_use,
        errors=errors,
    )

if __name__ == "__main__":
    import json

    print("Theseus Email Domain Analyzer")
    print("Enter an address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("email> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.strip().lower() in {"q", "quit", "exit", "bye"}:
            break

        result = analyze_email_domain(target)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))