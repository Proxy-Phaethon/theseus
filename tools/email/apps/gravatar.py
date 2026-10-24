"""
Gravatar public-profile lookup for Theseus.

Looks up a public Gravatar profile using the SHA-256 hash of an email
address. A match is a lead, not proof of account ownership.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request

from .base import ServiceResult

def check_gravatar(email: str) -> ServiceResult:
    """Check whether an email resolves to a public Gravatar profile."""

    observed_at = time.time()
    normalized = email.strip().lower()

    if (
        not normalized
        or normalized.count("@") != 1
        or any(char.isspace() for char in normalized)
    ):
        return ServiceResult(
            service="Gravatar",
            category="public_profile",
            status="error",
            url=None,
            evidence={},
            source="Gravatar API",
            observed_at=observed_at,
            error="Invalid email address",
        )

    email_hash = hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()

    endpoint = f"https://api.gravatar.com/v3/profiles/{email_hash}"

    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "Theseus-OSINT/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return ServiceResult(
                service="Gravatar",
                category="public_profile",
                status="not_found",
                url=None,
                evidence={"email_hash": email_hash},
                source="Gravatar API",
                observed_at=observed_at,
            )

        if exc.code == 429:
            error = "Gravatar rate limit reached"
        else:
            error = f"Gravatar returned HTTP {exc.code}"

        return ServiceResult(
            service="Gravatar",
            category="public_profile",
            status="error",
            url=None,
            evidence={},
            source="Gravatar API",
            observed_at=observed_at,
            error=error,
        )

    except (urllib.error.URLError, TimeoutError) as exc:
        return ServiceResult(
            service="Gravatar",
            category="public_profile",
            status="error",
            url=None,
            evidence={},
            source="Gravatar API",
            observed_at=observed_at,
            error=f"Network error: {exc}",
        )

    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ServiceResult(
            service="Gravatar",
            category="public_profile",
            status="error",
            url=None,
            evidence={},
            source="Gravatar API",
            observed_at=observed_at,
            error=f"Invalid API response: {exc}",
        )

    profile_url = payload.get("profile_url")

    if (
        not isinstance(profile_url, str)
        or not profile_url.startswith("https://gravatar.com/")
    ):
        return ServiceResult(
            service="Gravatar",
            category="public_profile",
            status="error",
            url=None,
            evidence={},
            source="Gravatar API",
            observed_at=observed_at,
            error="API response did not contain a valid profile URL",
        )

    evidence = {
        "display_name": payload.get("display_name"),
        "avatar_url": payload.get("avatar_url"),
        "email_hash": payload.get("hash", email_hash),
    }

    evidence = {
        key: value
        for key, value in evidence.items()
        if value is not None
    }

    return ServiceResult(
        service="Gravatar",
        category="public_profile",
        status="associated",
        url=profile_url,
        evidence=evidence,
        source="Gravatar API",
        observed_at=observed_at,
    )

if __name__ == "__main__":
    import json

    print("Theseus Gravatar Lookup")
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
            print("Please enter an email address.")
            continue

        print(
            json.dumps(
                check_gravatar(target).to_dict(),
                indent=2,
                ensure_ascii=False,
            )
        )