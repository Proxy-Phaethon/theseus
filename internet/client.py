##    HTTP communication
##    GET / POST / headers / cookies / sessions

from __future__ import annotations

from typing import Any

import httpx

from .exceptions import RequestError

class Client:
    """
    Low-level HTTP client used by the Internet layer.

    Handles:
    - HTTP requests
    - persistent sessions
    - headers
    - cookies
    - timeouts
    """

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> None:
        default_headers = {
            "User-Agent": "Theseus/0.1",
            "Accept": "*/*",
        }

        if headers:
            default_headers.update(headers)

        self._client = httpx.Client(
            timeout=timeout,
            headers=default_headers,
            follow_redirects=follow_redirects,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        try:
            response = self._client.request(
                method,
                url,
                params=params,
                data=data,
                json=json,
                headers=headers,
            )

            if raise_for_status:
                response.raise_for_status()

            return response

        except httpx.HTTPStatusError as exc:
            raise RequestError(
                f"{method.upper()} request failed: "
                f"{exc.response.status_code} {url} "
                f"{exc.response.text}"
            ) from exc

        except httpx.RequestError as exc:
            raise RequestError(
                f"{method.upper()} request failed: {url} ({exc})"
            ) from exc

    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            raise_for_status=raise_for_status,
        )

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return self.request(
            "POST",
            url,
            data=data,
            json=json,
            headers=headers,
        )

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._client.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()