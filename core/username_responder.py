from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.identifier import Entity

class UsernameResponder:
    EXCLUDED_FIELDS = {
        "source",
        "sources",
        "http_status",
        "response_time_s",
        "url_main",
    }

    def respond(
        self,
        entity: Entity,
        results: list[tuple[str, Any]],
    ) -> str:
        accounts: dict[tuple[str, str], dict[str, Any]] = {}

        for tool_name, result in results:
            if not isinstance(result, list):
                continue

            for account in result:
                if not isinstance(account, dict):
                    continue

                site = account.get("site") or account.get("site_name")
                url = account.get("url")

                if not site or not url:
                    continue

                normalized_url = self._normalize_url(url)
                key = (site.casefold(), normalized_url)

                if key not in accounts:
                    accounts[key] = {
                        "site": site,
                        "url": url,
                        "category": account.get("category"),
                        "extra": {},
                    }

                merged = accounts[key]

                if not merged["category"] and account.get("category"):
                    merged["category"] = account["category"]

                extra = account.get("extra", {})
                if isinstance(extra, dict):
                    for field, value in extra.items():
                        if field.casefold() in self.EXCLUDED_FIELDS:
                            continue
                        if field.startswith("_") or value is None:
                            continue

                        merged["extra"].setdefault(field, value)

                # Preserve useful top-level metadata from collectors.
                for field, value in account.items():
                    if field in {
                        "site",
                        "site_name",
                        "url",
                        "category",
                        "extra",
                    }:
                        continue

                    if field.casefold() in self.EXCLUDED_FIELDS:
                        continue

                    if field.startswith("_") or value is None:
                        continue

                    merged["extra"].setdefault(field, value)

        if not accounts:
            return "No accounts found."

        lines: list[str] = []

        for account in sorted(
            accounts.values(),
            key=lambda item: (
                item["site"].casefold(),
                item["url"].casefold(),
            ),
        ):
            lines.append(account["site"])

            if account["category"]:
                lines.append(f"  Category: {account['category']}")

            lines.append(f"  URL: {account['url']}")

            for field, value in sorted(
                account["extra"].items(),
                key=lambda item: item[0].casefold(),
            ):
                lines.append(f"  {field}: {value}")

            lines.append("")

        return "\n".join(lines).rstrip()

    @staticmethod
    def _normalize_url(url: str) -> str:
        try:
            parts = urlsplit(url)
            return urlunsplit(
                (
                    parts.scheme.lower(),
                    parts.netloc.lower(),
                    parts.path.rstrip("/"),
                    parts.query,
                    "",
                )
            )
        except (TypeError, ValueError):
            return url