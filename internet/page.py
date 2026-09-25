##    Common representation of a web page
##    URL, status, title, HTML, text, links, etc.

# internet/page.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bs4 import BeautifulSoup

from .exceptions import InternetError

@dataclass
class Page:
    """
    Backend-independent representation of a web page.

    A Page may be backed by either:
    - an HTTP response
    - a Playwright browser page
    """

    url: str
    status: int | None = None
    html: str = ""
    _backend: Any = None

    @property
    def title(self) -> str:
        """Return the page title."""

        if self._backend is not None:
            title = getattr(self._backend, "title", None)

            if callable(title):
                return title()

        soup = BeautifulSoup(self.html, "html.parser")

        if soup.title:
            return soup.title.get_text(strip=True)

        return ""

    @property
    def text(self) -> str:
        """Return visible page text."""

        if self._backend is not None:
            inner_text = getattr(self._backend, "inner_text", None)

            if callable(inner_text):
                return inner_text("body")

        soup = BeautifulSoup(self.html, "html.parser")

        for element in soup(["script", "style", "noscript"]):
            element.decompose()

        return soup.get_text(" ", strip=True)

    @property
    def links(self) -> list[str]:
        """Return links found on the page."""

        soup = BeautifulSoup(self.html, "html.parser")

        return [
            link.get("href")
            for link in soup.find_all("a", href=True)
        ]

    def click(self, selector: str) -> None:
        """Click an element using a CSS selector."""

        if self._backend is None:
            raise InternetError(
                "Clicking requires a browser-backed page"
            )

        self._backend.click(selector)

    def type(self, selector: str, text: str) -> None:
        """Type text into an element."""

        if self._backend is None:
            raise InternetError(
                "Typing requires a browser-backed page"
            )

        self._backend.fill(selector, text)

    def select(
        self,
        selector: str,
        value: str,
    ) -> None:
        """Select an option from a select element."""

        if self._backend is None:
            raise InternetError(
                "Selecting requires a browser-backed page"
            )

        self._backend.select_option(
            selector,
            value,
        )

    def submit(self, selector: str) -> None:
        """Submit a form."""

        if self._backend is None:
            raise InternetError(
                "Submitting requires a browser-backed page"
            )

        self._backend.locator(selector).press("Enter")

    def screenshot(
        self,
        path: str,
        *,
        full_page: bool = True,
    ) -> None:
        """Save a screenshot of the page."""

        if self._backend is None:
            raise InternetError(
                "Screenshots require a browser-backed page"
            )

        self._backend.screenshot(
            path=path,
            full_page=full_page,
        )

    def reload(self) -> None:
        """Reload the page."""

        if self._backend is None:
            raise InternetError(
                "Reloading requires a browser-backed page"
            )

        self._backend.reload()

    def back(self) -> None:
        """Navigate backward."""

        if self._backend is None:
            raise InternetError(
                "Navigation requires a browser-backed page"
            )

        self._backend.go_back()

    def forward(self) -> None:
        """Navigate forward."""

        if self._backend is None:
            raise InternetError(
                "Navigation requires a browser-backed page"
            )

        self._backend.go_forward()