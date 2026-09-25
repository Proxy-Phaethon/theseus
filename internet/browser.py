##    Playwright browser
##    tabs/pages
##    JavaScript-heavy sites
##    browser lifecycle

from __future__ import annotations

from playwright.sync_api import Browser, BrowserContext, Page as PlaywrightPage
from playwright.sync_api import Playwright, sync_playwright

from .exceptions import BrowserError

class BrowserSession:
    """
    Manages a real browser session for interactive web access.
    """

    def __init__(
        self,
        *,
        headless: bool = True,
        browser_type: str = "chromium",
        user_agent: str | None = None,
    ) -> None:
        self.headless = headless
        self.browser_type = browser_type
        self.user_agent = user_agent

        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: PlaywrightPage | None = None

    def start(self) -> None:
        """Start Playwright and create a browser context."""

        if self._playwright is not None:
            return

        try:
            self._playwright = sync_playwright().start()

            browser_launcher = getattr(
                self._playwright,
                self.browser_type,
                None,
            )

            if browser_launcher is None:
                raise BrowserError(
                    f"Unsupported browser: {self.browser_type}"
                )

            self._browser = browser_launcher.launch(
                headless=self.headless
            )

            context_options = {}

            if self.user_agent:
                context_options["user_agent"] = self.user_agent

            self._context = self._browser.new_context(
                **context_options
            )

            self._page = self._context.new_page()

        except Exception as exc:
            self.close()
            raise BrowserError("Failed to start browser") from exc

    @property
    def page(self) -> PlaywrightPage:
        """Return the active browser page."""

        if self._page is None:
            raise BrowserError("Browser session has not been started")

        return self._page

    def open(self, url: str) -> PlaywrightPage:
        """Navigate the browser to a URL."""

        self.start()

        try:
            self.page.goto(url)
            return self.page

        except Exception as exc:
            raise BrowserError(
                f"Failed to open URL: {url}"
            ) from exc

    def back(self) -> None:
        """Navigate backward."""

        try:
            self.page.go_back()
        except Exception as exc:
            raise BrowserError("Failed to navigate back") from exc

    def forward(self) -> None:
        """Navigate forward."""

        try:
            self.page.go_forward()
        except Exception as exc:
            raise BrowserError("Failed to navigate forward") from exc

    def reload(self) -> None:
        """Reload the current page."""

        try:
            self.page.reload()
        except Exception as exc:
            raise BrowserError("Failed to reload page") from exc

    def close(self) -> None:
        """Close the browser session."""

        if self._context is not None:
            self._context.close()
            self._context = None

        if self._browser is not None:
            self._browser.close()
            self._browser = None

        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

        self._page = None

    def __enter__(self) -> BrowserSession:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()