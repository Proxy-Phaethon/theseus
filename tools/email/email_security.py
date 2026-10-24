"""
Email security configuration collector for Theseus.

Collects publicly accessible email-security configuration.
Requires dnspython.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

import dns.exception
import dns.resolver

@dataclass
class EmailSecurityResult:
    domain: str
    spf: dict[str, Any]
    dmarc: dict[str, Any]
    mta_sts: dict[str, Any]
    tls_rpt: dict[str, Any]
    dnssec: dict[str, Any]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def _extract_domain(target: str) -> str | None:
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

def _txt_records(name: str) -> dict[str, Any]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
        records = [
            b"".join(record.strings).decode("utf-8", errors="replace")
            for record in answers
        ]
        return {"status": "found", "records": records, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"status": "not_found", "records": [], "error": "Name does not exist"}
    except dns.resolver.NoAnswer:
        return {"status": "not_found", "records": [], "error": None}
    except dns.exception.Timeout:
        return {"status": "error", "records": [], "error": "DNS query timed out"}
    except dns.exception.DNSException as exc:
        return {
            "status": "error",
            "records": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

def _find_tagged_record(records: list[str], prefix: str) -> str | None:
    for record in records:
        if record.lower().startswith(prefix.lower()):
            return record
    return None

def _collect_spf(domain: str) -> dict[str, Any]:
    result = _txt_records(domain)

    if result["status"] != "found":
        return {
            "status": result["status"],
            "record": None,
            "error": result["error"],
        }

    spf_records = [
        record for record in result["records"]
        if record.lower().startswith("v=spf1")
    ]

    return {
        "status": "found" if spf_records else "not_found",
        "record": spf_records[0] if len(spf_records) == 1 else None,
        "records": spf_records,
        "multiple_records": len(spf_records) > 1,
        "error": (
            "Multiple SPF records found"
            if len(spf_records) > 1
            else None
        ),
    }

def _collect_dmarc(domain: str) -> dict[str, Any]:
    result = _txt_records(f"_dmarc.{domain}")

    if result["status"] != "found":
        return {
            "status": result["status"],
            "record": None,
            "error": result["error"],
        }

    record = _find_tagged_record(result["records"], "v=DMARC1")

    if record is None:
        return {"status": "not_found", "record": None, "error": None}

    tags = {}
    for item in record.split(";"):
        if "=" in item:
            key, value = item.strip().split("=", 1)
            tags[key.strip().lower()] = value.strip()

    return {
        "status": "found",
        "record": record,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "percentage": tags.get("pct"),
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "tags": tags,
        "error": None,
    }

def _collect_mta_sts(domain: str) -> dict[str, Any]:
    result = _txt_records(f"_mta-sts.{domain}")

    if result["status"] != "found":
        return {
            "status": result["status"],
            "record": None,
            "policy": None,
            "error": result["error"],
        }

    record = _find_tagged_record(result["records"], "v=STSv1")

    if record is None:
        return {"status": "not_found", "record": None, "policy": None, "error": None}

    policy = None
    error = None

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Theseus-Email-Collector/1.0"},
        )
        with urllib.request.urlopen(request, timeout=5.0) as response:
            policy = response.read(65536).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        error = f"Policy fetch failed: {type(exc).__name__}: {exc}"

    return {
        "status": "found",
        "record": record,
        "policy_url": url,
        "policy": policy,
        "error": error,
    }

def _collect_tls_rpt(domain: str) -> dict[str, Any]:
    result = _txt_records(f"_smtp._tls.{domain}")

    if result["status"] != "found":
        return {
            "status": result["status"],
            "record": None,
            "error": result["error"],
        }

    record = _find_tagged_record(result["records"], "v=TLSRPTv1")

    return {
        "status": "found" if record else "not_found",
        "record": record,
        "error": None,
    }

def _collect_dnssec(domain: str) -> dict[str, Any]:
    """
    Inspect DNSSEC-related records exposed by the configured resolver.

    This is an indicative lookup, not cryptographic validation of the
    complete DNS chain.
    """
    result = {}

    for record_type in ("DNSKEY", "DS"):
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=5.0,
                raise_on_no_answer=False,
            )

            if answers.rrset is None:
                result[record_type.lower()] = {
                    "status": "not_found",
                    "records": [],
                }
            else:
                result[record_type.lower()] = {
                    "status": "found",
                    "records": [record.to_text() for record in answers],
                }
        except dns.exception.DNSException as exc:
            result[record_type.lower()] = {
                "status": "error",
                "records": [],
                "error": f"{type(exc).__name__}: {exc}",
            }

    return result

def collect_email_security(target: str) -> EmailSecurityResult:
    domain = _extract_domain(target)

    if not domain:
        raise ValueError("Could not extract a domain from target")

    domain = domain.encode("idna").decode("ascii").lower()
    errors = []

    try:
        spf = _collect_spf(domain)
        dmarc = _collect_dmarc(domain)
        mta_sts = _collect_mta_sts(domain)
        tls_rpt = _collect_tls_rpt(domain)
        dnssec = _collect_dnssec(domain)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        spf = dmarc = mta_sts = tls_rpt = dnssec = {
            "status": "error",
            "error": str(exc),
        }

    return EmailSecurityResult(
        domain=domain,
        spf=spf,
        dmarc=dmarc,
        mta_sts=mta_sts,
        tls_rpt=tls_rpt,
        dnssec=dnssec,
        errors=errors,
    )

if __name__ == "__main__":
    print("Theseus Email Security Collector")
    print("Enter a domain or email address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("target> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.strip().lower() in {"q", "quit", "exit", "bye"}:
            break

        try:
            result = collect_email_security(target)
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        except ValueError as exc:
            print(f"Error: {exc}")