"""
Email breach lookup for Theseus.

Uses the Have I Been Pwned (HIBP) API v3.
Requires HIBP_API_KEY in the environment.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

API_BASE = "https://haveibeenpwned.com/api/v3"
TIMEOUT = 15

@dataclass
class BreachResult:
    email: str
    status: str
    breach_count: int
    breaches: list[dict[str, Any]]
    source: str
    queried_at: float
    http_status: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def lookup_breaches(email: str) -> BreachResult:
    """Look up known breaches associated with an email address."""

    email = email.strip()

    if not email or "@" not in email:
        return BreachResult(
            email=email,
            status="invalid_target",
            breach_count=0,
            breaches=[],
            source="Have I Been Pwned",
            queried_at=time.time(),
            error="Expected an email address",
        )

    api_key = os.environ.get("HIBP_API_KEY", "").strip()

    if not api_key:
        return BreachResult(
            email=email,
            status="configuration_error",
            breach_count=0,
            breaches=[],
            source="Have I Been Pwned",
            queried_at=time.time(),
            error="HIBP_API_KEY is not set",
        )

    encoded_email = urllib.parse.quote(email, safe="")
    url = f"{API_BASE}/breachedaccount/{encoded_email}?truncateResponse=false"

    request = urllib.request.Request(
        url,
        headers={
            "hibp-api-key": api_key,
            "user-agent": "Theseus-OSINT",
            "accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            http_status = response.status
            payload = json.loads(response.read().decode("utf-8"))

        if not isinstance(payload, list):
            raise ValueError("Unexpected response format from HIBP")

        return BreachResult(
            email=email,
            status="found" if payload else "not_found",
            breach_count=len(payload),
            breaches=payload,
            source="Have I Been Pwned",
            queried_at=time.time(),
            http_status=http_status,
        )

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return BreachResult(
                email=email,
                status="not_found",
                breach_count=0,
                breaches=[],
                source="Have I Been Pwned",
                queried_at=time.time(),
                http_status=404,
            )

        messages = {
            400: "Invalid request",
            401: "API key missing or invalid",
            403: "Access forbidden; check API permissions",
            429: "Rate limit exceeded",
        }

        return BreachResult(
            email=email,
            status="error",
            breach_count=0,
            breaches=[],
            source="Have I Been Pwned",
            queried_at=time.time(),
            http_status=exc.code,
            error=messages.get(
                exc.code,
                f"HTTP error {exc.code}",
            ),
        )

    except (urllib.error.URLError, TimeoutError) as exc:
        return BreachResult(
            email=email,
            status="error",
            breach_count=0,
            breaches=[],
            source="Have I Been Pwned",
            queried_at=time.time(),
            error=f"Network error: {exc}",
        )

    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return BreachResult(
            email=email,
            status="error",
            breach_count=0,
            breaches=[],
            source="Have I Been Pwned",
            queried_at=time.time(),
            error=f"Response parsing error: {exc}",
        )

if __name__ == "__main__":
    print("Theseus Email Breach Lookup")
    print("Enter an email address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("email> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.casefold() in {"q", "quit", "exit", "bye"}:
            break

        if not target:
            continue

        print(
            json.dumps(
                lookup_breaches(target).to_dict(),
                indent=2,
                ensure_ascii=False,
            )
        )