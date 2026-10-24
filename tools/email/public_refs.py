"""
Public-reference discovery for Theseus.

Searches publicly indexed web pages for an exact email-address mention.
Uses DuckDuckGo HTML search; no API key or third-party package required.

Search results are leads, not proof of account ownership or wrongdoing.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Any

SEARCH_URL = "https://html.duckduckgo.com/html/"
TIMEOUT = 15

@dataclass
class PublicReferenceResult:
    email: str
    status: str
    result_count: int
    results: list[dict[str, str]]
    source: str
    queried_at: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class _DuckDuckGoParser(HTMLParser):
    """Extract result titles, URLs, and snippets from DDG HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None
        self._capture: str | None = None
        self._buffer: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        classes = attributes.get("class", "") or ""

        if tag == "div" and "result" in classes.split():
            self._current = {"title": "", "url": "", "snippet": ""}

        if self._current is None:
            return

        if tag == "a" and "result__a" in classes.split():
            self._current["url"] = attributes.get("href") or ""
            self._capture = "title"
            self._buffer = []

        elif tag == "a" and "result__snippet" in classes.split():
            self._capture = "snippet"
            self._buffer = []

        elif tag in {"div", "span"} and "result__snippet" in classes.split():
            self._capture = "snippet"
            self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._capture:
            self._buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._current is None:
            return

        if self._capture == "title" and tag == "a":
            self._current["title"] = " ".join(
                "".join(self._buffer).split()
            )
            self._capture = None
            self._buffer = []

        elif self._capture == "snippet" and tag in {"a", "div", "span"}:
            text = " ".join("".join(self._buffer).split())
            if text:
                self._current["snippet"] = text
            self._capture = None
            self._buffer = []

        if tag == "div":
            if self._current.get("title") and self._current.get("url"):
                self.results.append(self._current)
                self._current = None

def _clean_result_url(url: str) -> str:
    """Decode DuckDuckGo redirect URLs when possible."""
    if not url:
        return url

    parsed = urllib.parse.urlparse(url)

    if parsed.path == "/l/":
        params = urllib.parse.parse_qs(parsed.query)
        destination = params.get("uddg", [None])[0]
        if destination:
            return destination

    return url

def search_public_references(
    email: str,
    limit: int = 10,
) -> PublicReferenceResult:
    """Search public web indexes for an exact email-address mention."""

    email = email.strip()

    if not email or "@" not in email:
        return PublicReferenceResult(
            email=email,
            status="invalid_target",
            result_count=0,
            results=[],
            source="DuckDuckGo HTML",
            queried_at=time.time(),
            error="Expected an email address",
        )

    if limit < 1:
        return PublicReferenceResult(
            email=email,
            status="invalid_target",
            result_count=0,
            results=[],
            source="DuckDuckGo HTML",
            queried_at=time.time(),
            error="Limit must be at least 1",
        )

    query = f'"{email}"'
    params = urllib.parse.urlencode({"q": query})
    request = urllib.request.Request(
        f"{SEARCH_URL}?{params}",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; Theseus-OSINT/1.0)"
            ),
            "Accept": "text/html",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            page = response.read().decode("utf-8", errors="replace")

        parser = _DuckDuckGoParser()
        parser.feed(page)

        results = []
        seen_urls = set()

        for result in parser.results:
            url = _clean_result_url(result["url"])
            if not url or url in seen_urls:
                continue

            seen_urls.add(url)
            results.append(
                {
                    "title": unescape(result["title"]),
                    "url": url,
                    "snippet": unescape(result["snippet"]),
                }
            )

            if len(results) >= limit:
                break

        return PublicReferenceResult(
            email=email,
            status="found" if results else "not_found",
            result_count=len(results),
            results=results,
            source="DuckDuckGo HTML",
            queried_at=time.time(),
        )

    except urllib.error.HTTPError as exc:
        return PublicReferenceResult(
            email=email,
            status="error",
            result_count=0,
            results=[],
            source="DuckDuckGo HTML",
            queried_at=time.time(),
            error=f"HTTP error {exc.code}",
        )

    except (urllib.error.URLError, TimeoutError) as exc:
        return PublicReferenceResult(
            email=email,
            status="error",
            result_count=0,
            results=[],
            source="DuckDuckGo HTML",
            queried_at=time.time(),
            error=f"Network error: {exc}",
        )

if __name__ == "__main__":
    print("Theseus Public Email References")
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
                search_public_references(target).to_dict(),
                indent=2,
                ensure_ascii=False,
            )
        )