"""
GitLab email association lookup for Theseus.

Checks whether an email address is publicly associated with a GitLab
user account. A missing result does not prove that no account exists.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from .base import ServiceResult, make_result

API_URL = "https://gitlab.com/api/v4/users"
TIMEOUT = 10

def check_gitlab(email: str) -> ServiceResult:
    """Search GitLab for a user with a publicly associated email."""

    normalized_email = email.strip().casefold()

    if (
        not normalized_email
        or normalized_email.count("@") != 1
        or any(character.isspace() for character in normalized_email)
    ):
        return make_result(
            service="GitLab",
            category="developer",
            status="error",
            error="Invalid email address",
        )

    query = urllib.parse.urlencode(
        {
            "search": normalized_email,
            "per_page": 100,
        }
    )

    request = urllib.request.Request(
        f"{API_URL}?{query}",
        headers={
            "Accept": "application/json",
            "User-Agent": "Theseus-OSINT/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            status = "error"
            message = "GitLab rate limit reached"
        elif exc.code in {401, 403}:
            status = "error"
            message = f"GitLab denied the request (HTTP {exc.code})"
        else:
            status = "error"
            message = f"GitLab returned HTTP {exc.code}"

        return make_result(
            service="GitLab",
            category="developer",
            status=status,
            source="GitLab Users API",
            error=message,
        )

    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return make_result(
            service="GitLab",
            category="developer",
            status="error",
            source="GitLab Users API",
            error=f"GitLab request failed: {exc}",
        )

    except (json.JSONDecodeError, UnicodeDecodeError):
        return make_result(
            service="GitLab",
            category="developer",
            status="error",
            source="GitLab Users API",
            error="GitLab returned an invalid response",
        )

    if not isinstance(payload, list):
        return make_result(
            service="GitLab",
            category="developer",
            status="error",
            source="GitLab Users API",
            error="Unexpected GitLab response format",
        )

    exact_matches = [
        user
        for user in payload
        if isinstance(user, dict)
        and isinstance(user.get("public_email"), str)
        and user["public_email"].strip().casefold() == normalized_email
    ]

    if exact_matches:
        user = exact_matches[0]
        username = user.get("username")

        profile_url = (
            f"https://gitlab.com/{urllib.parse.quote(username, safe='')}"
            if isinstance(username, str) and username
            else None
        )

        return make_result(
            service="GitLab",
            category="developer",
            status="associated",
            url=profile_url,
            evidence={"match_type": "exact_public_email"},
            source="GitLab Users API",
        )

    return make_result(
        service="GitLab",
        category="developer",
        status="unknown",
        source="GitLab Users API",
        evidence={"reason": "No exact public-email match was returned"},
    )