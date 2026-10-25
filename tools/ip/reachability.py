"""Assess IP reachability using standard-library network probes.

Probes:
- ICMP echo, when the system's ping utility is available.
- TCP connection attempts to a small set of common ports.

No API keys or third-party Python packages are required.

Limitations:
- ICMP may be blocked even when the target is online.
- TCP results only describe the tested ports at the time of testing.
- A failed probe is inconclusive, not proof that an IP is offline.
"""

from __future__ import annotations

import ipaddress
import platform
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

TIMEOUT = 2.0
TCP_PORTS = (443, 80, 53, 22)
MAX_PING_OUTPUT = 4096

def _ping_command(ip: str) -> list[str] | None:
    """Build a bounded ping command for the current operating system."""
    system = platform.system().lower()

    if system == "windows":
        return ["ping", "-n", "1", "-w", str(int(TIMEOUT * 1000)), ip]

    if system in {"linux", "darwin", "freebsd"}:
        return ["ping", "-c", "1", "-W", str(int(TIMEOUT)), ip]

    return None

def _icmp_probe(ip: str) -> dict[str, Any]:
    """Try one ICMP echo request using the system ping utility."""
    ping_path = shutil.which("ping")

    if not ping_path:
        return {
            "status": "not_available",
            "reason": "The system ping utility was not found",
            "latency_ms": None,
        }

    command = _ping_command(ip)

    if not command:
        return {
            "status": "not_available",
            "reason": f"Unsupported operating system: {platform.system()}",
            "latency_ms": None,
        }

    command[0] = ping_path
    started = time.perf_counter()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TIMEOUT + 2,
            check=False,
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        # Bound retained output. The command itself only sends one packet.
        output = (result.stdout or "")[:MAX_PING_OUTPUT]
        output += (result.stderr or "")[:MAX_PING_OUTPUT]

        if result.returncode == 0:
            latency = _extract_ping_latency(output)

            return {
                "status": "responsive",
                "latency_ms": latency if latency is not None else elapsed_ms,
                "reason": None,
            }

        return {
            "status": "no_response",
            "latency_ms": None,
            "reason": "Ping received no successful reply",
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "no_response",
            "latency_ms": None,
            "reason": "Ping command timed out",
        }
    except OSError as exc:
        return {
            "status": "error",
            "latency_ms": None,
            "reason": str(exc),
        }

def _extract_ping_latency(output: str) -> float | None:
    """Extract a typical ping time value from command output."""
    import re

    patterns = (
        r"time[=<]\s*([\d.]+)\s*ms",
        r"time\s*=\s*([\d.]+)\s*ms",
        r"Average\s*=\s*(\d+)\s*ms",
    )

    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                continue

    # Some platforms report a successful reply without a parseable time.
    return None

def _tcp_probe(ip: str, port: int) -> dict[str, Any]:
    """Attempt a TCP connection and measure connection latency."""
    started = time.perf_counter()

    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        return {
            "port": port,
            "status": "connected",
            "latency_ms": elapsed_ms,
            "reason": None,
        }

    except socket.timeout:
        return {
            "port": port,
            "status": "no_response",
            "latency_ms": None,
            "reason": "Connection attempt timed out",
        }
    except ConnectionRefusedError:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        return {
            "port": port,
            "status": "refused",
            "latency_ms": elapsed_ms,
            "reason": "Connection was actively refused",
        }
    except OSError as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        return {
            "port": port,
            "status": "error",
            "latency_ms": elapsed_ms,
            "reason": str(exc),
        }

def run(target: str) -> dict[str, Any]:
    """Assess reachability for an IPv4 or IPv6 target."""
    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return {
            "status": "error",
            "target": str(target),
            "error": "Invalid IP address",
        }

    ip = str(address)

    if not address.is_global:
        return {
            "status": "not_checked",
            "target": ip,
            "reason": "Active probes are skipped for non-global IPs",
        }

    checked_at = datetime.now(timezone.utc).isoformat()

    icmp = _icmp_probe(ip)
    tcp_results = [_tcp_probe(ip, port) for port in TCP_PORTS]

    connected_ports = [
        result["port"]
        for result in tcp_results
        if result["status"] == "connected"
    ]

    refused_ports = [
        result["port"]
        for result in tcp_results
        if result["status"] == "refused"
    ]

    tcp_responded = bool(connected_ports or refused_ports)
    icmp_responded = icmp["status"] == "responsive"

    if icmp_responded or tcp_responded:
        assessment = "responsive"
    elif icmp["status"] == "error" and all(
        result["status"] == "error" for result in tcp_results
    ):
        assessment = "inconclusive"
    else:
        assessment = "no_response"

    return {
        "status": "success",
        "target": ip,
        "checked_at": checked_at,
        "assessment": assessment,
        "summary": {
            "icmp_responsive": icmp_responded,
            "tcp_responsive": tcp_responded,
            "tcp_connected_ports": connected_ports,
            "tcp_refused_ports": refused_ports,
        },
        "icmp": icmp,
        "tcp": {
            "ports_tested": list(TCP_PORTS),
            "results": tcp_results,
        },
        "limitations": [
            "No response does not prove that the target is offline.",
            "ICMP may be filtered independently of TCP traffic.",
            "TCP connection latency is not equivalent to ICMP round-trip time.",
            "Only the listed TCP ports were tested.",
            "Results reflect the network path and time of this check.",
        ],
    }

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Assess IP reachability using ICMP and TCP probes"
    )
    parser.add_argument("target", help="IPv4 or IPv6 address")
    args = parser.parse_args()

    print(json.dumps(run(args.target), indent=2))