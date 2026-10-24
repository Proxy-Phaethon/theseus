"""
Email breach lookup for Theseus.

Uses the free XposedOrNot API.
No API key or third-party Python package required.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

API_BASE = "https://api.xposedornot.com/v1"
TIMEOUT = 15

@dataclass
class BreachResult:
    email: str
    status: str
    breach_count: int
    breaches: list[Any]
    source: str
    queried_at: float
    raw_response: dict[str, Any]
    http_status: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def lookup_breaches(email: str) -> BreachResult:
    """Check whether an email appears in known data breaches."""

    email = email.strip()
    source = "XposedOrNot"

    if not email or "@" not in email:
        return BreachResult(
            email=email,
            status="invalid_target",
            breach_count=0,
            breaches=[],
            source=source,
            queried_at=time.time(),
            raw_response={},
            error="Expected an email address",
        )

    encoded_email = urllib.parse.quote(email, safe="")
    url = f"{API_BASE}/check-email/{encoded_email}"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Theseus-OSINT",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            http_status = response.status
            payload = json.loads(response.read().decode("utf-8"))

        if not isinstance(payload, dict):
            raise ValueError("Unexpected API response format")

        if payload.get("Error") == "Not found":
            return BreachResult(
                email=email,
                status="not_found",
                breach_count=0,
                breaches=[],
                source=source,
                queried_at=time.time(),
                raw_response=payload,
                http_status=http_status,
            )

        if payload.get("status") != "success":
            return BreachResult(
                email=email,
                status="error",
                breach_count=0,
                breaches=[],
                source=source,
                queried_at=time.time(),
                raw_response=payload,
                http_status=http_status,
                error="API returned an unrecognized response",
            )

        raw_breaches = payload.get("breaches", [])

        if not isinstance(raw_breaches, list):
            raise ValueError("Unexpected breach data format")

        breach_names = []

        for item in raw_breaches:
            if isinstance(item, list):
                breach_names.extend(item)
            elif isinstance(item, str):
                breach_names.append(item)

        return BreachResult(
            email=email,
            status="found" if breach_names else "not_found",
            breach_count=len(breach_names),
            breaches=breach_names,
            source=source,
            queried_at=time.time(),
            raw_response=payload,
            http_status=http_status,
        )

    except urllib.error.HTTPError as exc:
        messages = {
            400: "Invalid request",
            404: "No matching breach data found",
            429: (
                "Rate limit exceeded. Check the Retry-After header "
                "and try again later."
            ),
            500: "XposedOrNot server error",
            502: "XposedOrNot gateway error",
            503: "XposedOrNot service unavailable",
        }

        status = "not_found" if exc.code == 404 else "error"

        return BreachResult(
            email=email,
            status=status,
            breach_count=0,
            breaches=[],
            source=source,
            queried_at=time.time(),
            raw_response={},
            http_status=exc.code,
            error=(
                None if status == "not_found"
                else messages.get(exc.code, f"HTTP error {exc.code}")
            ),
        )

    except (urllib.error.URLError, TimeoutError) as exc:
        return BreachResult(
            email=email,
            status="error",
            breach_count=0,
            breaches=[],
            source=source,
            queried_at=time.time(),
            raw_response={},
            error=f"Network error: {exc}",
        )

    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return BreachResult(
            email=email,
            status="error",
            breach_count=0,
            breaches=[],
            source=source,
            queried_at=time.time(),
            raw_response={},
            error=f"Response parsing error: {exc}",
        )

if __name__ == "__main__":
    print("Theseus Email Breach Lookup")
    print("Source: XposedOrNot")
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

        result = lookup_breaches(target)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))