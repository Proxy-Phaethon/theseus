"""
Reverse DNS lookup for Theseus.

Retrieves PTR hostnames associated with an IPv4 or IPv6 address.
Uses the system's configured name-resolution service.

No third-party Python packages or API keys are required.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from typing import Any

def run(target: str) -> dict[str, Any]:
    """Look up reverse DNS names for an IP address."""
    observed_at = time.time()
    original = target

    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        return {
            "module": "reverse_dns",
            "target": original,
            "status": "error",
            "observed_at": observed_at,
            "error": "Target is not a valid IPv4 or IPv6 address",
        }

    if not address.is_global:
        return {
            "module": "reverse_dns",
            "target": str(address),
            "status": "not_checked",
            "observed_at": observed_at,
            "error": "Reverse DNS lookup skipped for a non-global address",
        }

    try:
        hostname, aliases, resolved_addresses = socket.gethostbyaddr(
            str(address)
        )

        hostnames = list(dict.fromkeys(
            name.rstrip(".")
            for name in [hostname, *aliases]
            if name
        ))

        return {
            "module": "reverse_dns",
            "target": str(address),
            "status": "success",
            "source": "System DNS resolver",
            "observed_at": time.time(),
            "hostnames": hostnames,
            "resolved_addresses": list(dict.fromkeys(resolved_addresses)),
        }

    except socket.herror as exc:
        return {
            "module": "reverse_dns",
            "target": str(address),
            "status": "not_found",
            "source": "System DNS resolver",
            "observed_at": time.time(),
            "hostnames": [],
            "error": str(exc),
        }

    except (socket.gaierror, OSError) as exc:
        return {
            "module": "reverse_dns",
            "target": str(address),
            "status": "error",
            "source": "System DNS resolver",
            "observed_at": time.time(),
            "hostnames": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

if __name__ == "__main__":
    while True:
        try:
            target = input("ip> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.casefold() in {"q", "quit", "exit", "bye"}:
            break

        if not target:
            continue

        print(json.dumps(run(target), indent=2, ensure_ascii=False))