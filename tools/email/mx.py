"""
MX and mail-server resolution for Theseus.

Queries DNS for MX records and resolves the advertised mail servers.
Does not verify that an individual mailbox exists.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import asdict, dataclass
from typing import Any

import dns.exception
import dns.resolver

@dataclass
class MailServer:
    hostname: str
    priority: int
    ipv4: list[str]
    ipv6: list[str]
    resolution_errors: list[str]

@dataclass
class MXResult:
    domain: str
    status: str
    accepts_email: bool | None
    mail_servers: list[dict[str, Any]]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def _extract_domain(target: str) -> str | None:
    """Accept either a domain or an email address."""
    value = target.strip()

    if "@" not in value:
        return value.rstrip(".") or None

    quoted = False
    escaped = False
    separators = []

    for index, char in enumerate(value):
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

    return value[separators[0] + 1:].rstrip(".") or None

def _resolve_addresses(hostname: str) -> tuple[list[str], list[str], list[str]]:
    ipv4: list[str] = []
    ipv6: list[str] = []
    errors: list[str] = []

    for record_type, destination in (("A", ipv4), ("AAAA", ipv6)):
        try:
            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=5.0,
            )
            for answer in answers:
                address = str(answer)
                # Defensive validation of the returned address.
                parsed = ipaddress.ip_address(address)
                destination.append(str(parsed))
        except dns.resolver.NXDOMAIN:
            errors.append(f"{record_type}: hostname does not exist")
        except dns.resolver.NoAnswer:
            # No records of this address family is normal.
            pass
        except dns.resolver.NoNameservers:
            errors.append(f"{record_type}: no nameserver returned an answer")
        except dns.exception.Timeout:
            errors.append(f"{record_type}: DNS query timed out")
        except (dns.exception.DNSException, ValueError, OSError) as exc:
            errors.append(f"{record_type}: {type(exc).__name__}: {exc}")

    return ipv4, ipv6, errors

def lookup_mx(target: str) -> MXResult:
    """
    Look up MX records for a domain or email address.

    Status values:
      - found: one or more usable MX records were returned
      - null_mx: explicit Null MX record
      - no_mx: no MX records were published
      - not_found: domain does not exist
      - error: DNS lookup failed or returned an unusable response
      - invalid_target: no domain could be extracted
    """
    domain = _extract_domain(target)

    if not domain:
        return MXResult(
            domain="",
            status="invalid_target",
            accepts_email=None,
            mail_servers=[],
            errors=["Could not extract a domain from the target"],
        )

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
    except dns.resolver.NXDOMAIN:
        return MXResult(
            domain=domain,
            status="not_found",
            accepts_email=False,
            mail_servers=[],
            errors=["Domain does not exist according to DNS"],
        )
    except dns.resolver.NoAnswer:
        return MXResult(
            domain=domain,
            status="no_mx",
            accepts_email=None,
            mail_servers=[],
            errors=["No MX records were published"],
        )
    except dns.resolver.NoNameservers:
        return MXResult(
            domain=domain,
            status="error",
            accepts_email=None,
            mail_servers=[],
            errors=["No nameserver returned a usable MX response"],
        )
    except dns.exception.Timeout:
        return MXResult(
            domain=domain,
            status="error",
            accepts_email=None,
            mail_servers=[],
            errors=["MX DNS query timed out"],
        )
    except dns.exception.DNSException as exc:
        return MXResult(
            domain=domain,
            status="error",
            accepts_email=None,
            mail_servers=[],
            errors=[f"MX DNS query failed: {type(exc).__name__}: {exc}"],
        )

    records = sorted(
        (
            int(answer.preference),
            str(answer.exchange).rstrip(".").lower(),
        )
        for answer in answers
    )

    if records == [(0, "")]:
        return MXResult(
            domain=domain,
            status="null_mx",
            accepts_email=False,
            mail_servers=[],
            errors=[],
        )

    if any(hostname == "" for _, hostname in records):
        return MXResult(
            domain=domain,
            status="error",
            accepts_email=None,
            mail_servers=[],
            errors=["Malformed or mixed Null MX response"],
        )

    mail_servers: list[dict[str, Any]] = []

    for priority, hostname in records:
        ipv4, ipv6, resolution_errors = _resolve_addresses(hostname)

        server = MailServer(
            hostname=hostname,
            priority=priority,
            ipv4=ipv4,
            ipv6=ipv6,
            resolution_errors=resolution_errors,
        )
        mail_servers.append(asdict(server))

    return MXResult(
        domain=domain,
        status="found",
        accepts_email=True,
        mail_servers=mail_servers,
        errors=[],
    )

if __name__ == "__main__":
    import json

    print("Theseus MX Lookup")
    print("Enter a domain or email address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("target> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.strip().lower() in {"q", "quit", "exit", "bye"}:
            break

        result = lookup_mx(target)
        print(json.dumps(result.to_dict(), indent=2))