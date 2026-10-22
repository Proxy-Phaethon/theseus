import hashlib
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

class PlaywrightTool:
    @staticmethod
    def _get_redirects(request):
        chain = []

        while request is not None:
            chain.append(request)
            request = request.redirected_from

        chain.reverse()

        redirects = []

        for index, item in enumerate(chain[:-1]):
            response = item.response()

            redirects.append({
                "url": item.url,
                "status_code": response.status if response else None,
                "location": chain[index + 1].url,
            })

        return redirects

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        requests_seen = []
        failed_requests = []
        console_errors = []
        page_errors = []

        start = time.perf_counter()

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            page.on(
                "request",
                lambda request: requests_seen.append({
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                }),
            )

            page.on(
                "requestfailed",
                lambda request: failed_requests.append({
                    "url": request.url,
                    "error": request.failure,
                }),
            )

            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )

            page.on(
                "pageerror",
                lambda error: page_errors.append(str(error)),
            )

            try:
                response = page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=30000,
                )

                page.wait_for_timeout(1500)

                dom = page.content()

                links = page.locator("a[href]").evaluate_all(
                    """elements => elements.map(a => ({
                        text: (a.innerText || a.textContent || '').trim(),
                        href: a.href
                    })).slice(0, 500)"""
                )

                forms = page.locator("form").evaluate_all(
                    """elements => elements.map(form => ({
                        action: form.action,
                        method: (form.method || 'get').toUpperCase(),
                        fields: Array.from(form.elements).map(el => ({
                            name: el.name || '',
                            type: el.type || '',
                            required: !!el.required
                        }))
                    })).slice(0, 100)"""
                )

                result = {
                    "requested_url": url,
                    "final_url": page.url,
                    "title": page.title(),
                    "status_code": (
                        response.status if response is not None else None
                    ),
                    "content_type": (
                        response.headers.get("content-type")
                        if response is not None
                        else None
                    ),
                    "redirects": (
                        self._get_redirects(response.request)
                        if response is not None
                        else []
                    ),
                    "dom_length": len(dom),
                    "dom_sha256": hashlib.sha256(
                        dom.encode("utf-8")
                    ).hexdigest(),
                    "links": links,
                    "forms": forms,
                    "requests": requests_seen,
                    "failed_requests": failed_requests,
                    "console_errors": console_errors,
                    "page_errors": page_errors,
                    "elapsed_ms": round(
                        (time.perf_counter() - start) * 1000
                    ),
                }

            finally:
                browser.close()

        return result