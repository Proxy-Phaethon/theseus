from __future__ import annotations

from typing import Any

from core.identifier import Entity

class EmailResponder:
    def respond(
        self,
        entity: Entity,
        results: list[tuple[str, Any]],
    ) -> str:
        data = {
            tool_name.lower(): result
            for tool_name, result in results
        }

        disify = self._tool(data, "disify")
        xposedornot = self._tool(data, "xposedornot")
        holehe = self._tool(data, "holehe")
        user_scanner = self._tool(data, "user_scanner")
        github = self._tool(data, "github")

        sections = []

        identity = self._identity(entity.value, disify)
        if identity:
            sections.append(("Email Identity", identity))

        infrastructure = self._infrastructure(disify)
        if infrastructure:
            sections.append(("Email Infrastructure", infrastructure))

        breaches = self._breaches(xposedornot)
        if breaches:
            sections.append(("Breach Exposure", breaches))

        accounts = self._accounts(user_scanner, holehe)
        if accounts:
            sections.append(("Account Discovery", accounts))

        footprint = self._github(github)
        if footprint:
            sections.append(("Public Code Footprint", footprint))

        return self._format_sections(sections)

    @staticmethod
    def cross_scan(results: list[tuple[str, Any]]) -> list[str]:
        """Extract and print usernames discovered by email User Scanner results."""
        data = {
            tool_name.lower(): result
            for tool_name, result in results
        }
        user_scanner = EmailResponder._tool(data, "user_scanner")

        usernames = []
        seen = set()

        if isinstance(user_scanner, list):
            for record in user_scanner:
                if not isinstance(record, dict):
                    continue
                if str(record.get("status") or "").strip().lower() != "registered":
                    continue

                extra = record.get("extra")
                if not isinstance(extra, dict):
                    continue

                login = extra.get("login")
                if not isinstance(login, str):
                    continue

                username = login.strip()
                if not username or not username.isascii():
                    continue

                # Keep candidates compatible with Identifier's username syntax.
                if not (1 <= len(username) <= 30):
                    continue
                if any(
                    not (char.isalnum() or char in "._-")
                    for char in username
                ):
                    continue

                normalized = username.casefold()
                if normalized not in seen:
                    seen.add(normalized)
                    usernames.append(username)

        if not usernames:
            print("No usernames found.")
            return []