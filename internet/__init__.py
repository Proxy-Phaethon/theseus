from __future__ import annotations

from .browser import BrowserSession
from .client import Client
from .page import Page

class Internet:
    """
    Public interface to Theseus' internet layer.
    """

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        user_agent: str = "Theseus/0.1",
        headless: bool = True,
    ) -> None:
        self.client = Client(
            timeout=timeout,
            headers={"User-Agent": user_agent},
        )

        self.browser = BrowserSession(
            headless=headless,
            user_agent=user_agent,
        )

    def open(self, url: str) -> Page:
        """Open a URL using HTTP."""

        response = self.client.get(url)

        return Page(
            url=str(response.url),
            status=response.status_code,
            html=response.text,
        )

    def browse(self, url: str) -> Page:
        """Open a URL using a real browser."""

        browser_page = self.browser.open(url)

        return Page(
            url=browser_page.url,
            html=browser_page.content(),
            _backend=browser_page,
        )

    def close(self) -> None:
        """Close all internet resources."""

        self.client.close()
        self.browser.close()

    def __enter__(self) -> Internet:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

__all__ = [
    "Internet",
    "Client",
    "BrowserSession",
    "Page",
]