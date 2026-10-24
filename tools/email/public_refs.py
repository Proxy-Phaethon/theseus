"""
Public-reference discovery for Theseus.

Searches Mwmbl's public web index for references to an email address.
Uses the JSON API without an API key or third-party package.

No results means the provider found no matches, not that the email
address has no public presence.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass

API_URL = "https://api.mwmbl.org/api/v2/search/"
TIMEOUT = 15
USER_AGENT = "Theseus-OSINT/0.1"

@dataclass
class PublicReferenceResult:
    email: str
    status: str
    result_count: int
    results: list[dict]
    source: str
    queried_at: float
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def search_public_references(
    email: str,
    limit: int = 10,
) -> PublicReferenceResult:
    email = email.strip()

    if not email or "@" not in email:
        return PublicReferenceResult(
            email=email,
            status="invalid_target",
            result_count=0,
            results=[],
            source="Mwmbl",
            queried_at=time.time(),
            error="A valid-looking email address is required.",
        )

    if limit < 1:
        return PublicReferenceResult(
            email=email,
            status="invalid_target",
            result_count=0,
            results=[],
            source="Mwmbl",
            queried_at=time.time(),
            error="Limit must be at least 1.",
        )

    query = f'"{email}"'
    params = urllib.parse.urlencode({"q": query})
    request = urllib.request.Request(
        f"{API_URL}?{params}",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = json.loads(
                response.read().decode("utf-8", errors="replace")
            )

        raw_results = payload.get("results", [])
        if not isinstance(raw_results, list):
            raise ValueError("Unexpected results format in Mwmbl response.")

        results = []
        seen_urls = set()

        for item in raw_results:
            if not isinstance(item, dict):
                continue

            url = item.get("url")
            if not isinstance(url, str) or not url:
                continue

            if url in seen_urls:
                continue
            seen_urls.add(url)

            results.append({
                "title": item.get("title", ""),
                "url": url,
                "snippet": item.get("content", ""),
                "source": item.get("engine", "mwmbl"),
                "score": item.get("score"),
            })

            if len(results) >= limit:
                break

        return PublicReferenceResult(
            email=email,
            status="found" if results else "not_found",
            result_count=len(results),
            results=results,
            source="Mwmbl",
            queried_at=time.time(),
        )

    except urllib.error.HTTPError as exc:
        return PublicReferenceResult(
            email=email,
            status="error",
            result_count=0,
            results=[],
            source="Mwmbl",
            queried_at=time.time(),
            error=f"HTTP {exc.code}: {exc.reason}",
        )

    except (urllib.error.URLError, TimeoutError) as exc:
        return PublicReferenceResult(
            email=email,
            status="error",
            result_count=0,
            results=[],
            source="Mwmbl",
            queried_at=time.time(),
            error=f"Network error: {exc}",
        )

    except (json.JSONDecodeError, ValueError) as exc:
        return PublicReferenceResult(
            email=email,
            status="error",
            result_count=0,
            results=[],
            source="Mwmbl",
            queried_at=time.time(),
            error=f"Invalid API response: {exc}",
        )

if __name__ == "__main__":
    while True:
        try:
            target = input("\nemail> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.casefold() in {"q", "q.", "quit", "bye"}:
            break

        result = search_public_references(target)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))