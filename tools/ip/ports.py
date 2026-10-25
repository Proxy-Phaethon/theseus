"""
TCP port checks for Theseus.

Tests a conservative list of common TCP ports using connection attempts.
This is active network probing, not passive intelligence collection.

No third-party Python packages or API keys are required.
Only scan systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from typing import Any

TIMEOUT = 1.0

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
}

def run(target: str) -> dict[str, Any]:
    """Check a fixed set of common TCP ports on a public IP address."""
    observed_at = time.time()
    original = target

    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        return {
            "module": "ports",
            "target": original,
            "status": "error",
            "observed_at": observed_at,
            "error": "Target is not a valid IPv4 or IPv6 address",
        }

    if not address.is_global:
        return {
            "module": "ports",
            "target": str(address),
            "status": "not_checked",
            "observed_at": observed_at,
            "error": "Port checks skipped for a non-global address",
        }

    results: list[dict[str, Any]] = []

    for port, service in COMMON_PORTS.items():
        try:
            with socket.socket(
                socket.AF_INET6 if address.version == 6 else socket.AF_INET,
                socket.SOCK_STREAM,
            ) as sock:
                sock.settimeout(TIMEOUT)
                result_code = sock.connect_ex((str(address), port))

            if result_code == 0:
                state = "open"
            elif result_code in {111, 61, 10061}:
                state = "closed"
            else:
                state = "no_response"

            results.append({
                "port": port,
                "service": service,
                "state": state,
            })

        except (OSError, socket.timeout) as exc:
            results.append({
                "port": port,
                "service": service,
                "state": "error",
                "error": f"{type(exc).__name__}: {exc}",
            })

    open_ports = [
        item for item in results if item["state"] == "open"
    ]

    return {
        "module": "ports",
        "target": str(address),
        "status": "success",
        "source": "Direct TCP connection checks",
        "observed_at": time.time(),
        "scan": {
            "protocol": "TCP",
            "method": "connect",
            "ports_checked": len(COMMON_PORTS),
            "timeout_seconds": TIMEOUT,
        },
        "summary": {
            "open": len(open_ports),
            "closed": sum(
                item["state"] == "closed" for item in results
            ),
            "no_response": sum(
                item["state"] == "no_response" for item in results
            ),
            "errors": sum(
                item["state"] == "error" for item in results
            ),
        },
        "open_ports": open_ports,
        "results": results,
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