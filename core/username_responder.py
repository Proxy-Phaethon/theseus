from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.identifier import Entity

class UsernameResponder:
    def respond(
        self,
        entity: Entity,
        results: list[tuple[str, Any]],
    ) -> str:
        accounts: dict[str, dict[str, Any]] = {}

        for tool_name, result in results:
            if not isinstance(result, list):
                continue

            for record in result:
                if not isinstance(record, dict):
                    continue

                site = record.get("site") or record.get("site_name")
                url = record.get("url")

                if not isinstance(site, str) or not site.strip():
                    continue

                if not isinstance(url, str) or not url.strip():
                    continue

                key = self._normalize_url(url)

                if not key:
                    continue

                source = record.get("source") or tool_name
                category = record.get("category")
                extra = record.get("extra")

                if key not in accounts:
                    accounts[key] = {
                        "site": site.strip(),
                        "url": url.strip(),
                        "category": None,
                        "sources": set(),
                        "extra": {},
                    }

                account = accounts[key]
                account["sources"].add(source)

                if not account["category"] and isinstance(category, str):
                    account["category"] = category

                if isinstance(extra, dict):
                    for field, value in extra.items():
                        if value is not None and value != "":
                            account["extra"].setdefault(field, value)

        if not accounts:
            return "No accounts found."

        lines = []

        for account in sorted(
            accounts.values(),
            key=lambda item: item["site"].casefold(),
        ):
            lines.append(account["site"])

            if account["category"]:
                lines.append(f"  Category: {account['category']}")

            lines.append(f"  URL: {account['url']}")
            lines.append(
                f"  Sources: {', '.join(sorted(account['sources']))}"
            )

            if account["extra"]:
                for field, value in account["extra"].items():
                    lines.append(f"  {field}: {value}")

            lines.append("")

        return "\n".join(lines).rstrip()

    @staticmethod
    def _normalize_url(url: str) -> str:
        try:
            parsed = urlsplit(url.strip())

            if parsed.scheme.lower() not in {"http", "https"}:
                return ""

            if not parsed.hostname:
                return ""

            return urlunsplit((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
                parsed.query,
                "",
            ))
        except ValueError:
            return ""