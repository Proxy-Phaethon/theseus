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
            tool_name: result
            for tool_name, result in results
        }

        xposedornot = self._tool(data, "xposedornot")
        disify = self._tool(data, "disify")
        github = self._tool(data, "github")
        holehe = self._tool(data, "holehe")

        sections = []

        self._add_section(
            sections,
            "Email Identity",
            self._identity(entity, xposedornot, disify),
        )

        self._add_section(
            sections,
            "Email Infrastructure",
            self._infrastructure(disify),
        )

        self._add_section(
            sections,
            "Breach Exposure",
            self._breaches(xposedornot),
        )

        self._add_section(
            sections,
            "Associated Accounts",
            self._accounts(holehe),
        )

        self._add_section(
            sections,
            "Code & Developer Footprint",
            self._github(github),
        )

        return self._format_sections(sections)

    @staticmethod
    def _tool(data: dict[str, Any], name: str) -> Any:
        for tool_name, result in data.items():
            if name in tool_name.lower():
                return result

        return {}

    @staticmethod
    def _add_section(
        sections: list[tuple[str, list[str]]],
        title: str,
        lines: list[str],
    ) -> None:
        if lines:
            sections.append((title, lines))

    @staticmethod
    def _format_sections(
        sections: list[tuple[str, list[str]]],
    ) -> str:
        output = []

        for title, lines in sections:
            output.append(title)

            for line in lines:
                output.append(f"  {line}")

            output.append("")

        return "\n".join(output).rstrip()

    def _identity(self, entity, xposedornot, disify):
        lines = []

        email = (
            xposedornot.get("email")
            if isinstance(xposedornot, dict)
            else None
        )

        if not email:
            email = getattr(entity, "value", None)

        if email:
            lines.append(f"Email: {email}")

        if not isinstance(disify, dict):
            return lines

        domain = disify.get("domain")
        if domain:
            lines.append(f"Domain: {domain} [DisifyTool]")

        domain_info = disify.get("domain_info") or {}

        if isinstance(domain_info, dict):
            tld = domain_info.get("tld")
            if tld:
                lines.append(f"TLD: .{tld} [DisifyTool]")

            is_subdomain = domain_info.get("is_subdomain")
            if is_subdomain is not None:
                value = "Yes" if is_subdomain else "No"
                lines.append(
                    f"Subdomain: {value} [DisifyTool]"
                )

        fields = (
            ("format", "Format", {True: "Valid", False: "Invalid"}),
            ("disposable", "Disposable", {True: "Yes", False: "No"}),
            ("role", "Role Account", {True: "Yes", False: "No"}),
            ("free", "Free Provider", {True: "Yes", False: "No"}),
            ("dns", "DNS", {True: "Available", False: "Not detected"}),
            ("whitelist", "Whitelist", {True: "Yes", False: "No"}),
        )

        for key, label, values in fields:
            value = disify.get(key)

            if isinstance(value, bool):
                lines.append(
                    f"{label}: {values[value]} [DisifyTool]"
                )

        confidence = disify.get("confidence")
        if confidence is not None:
            lines.append(
                f"Confidence: {confidence} [DisifyTool]"
            )

        return lines

    def _infrastructure(self, disify):
        if not isinstance(disify, dict):
            return []

        mx_records = disify.get("mx_info") or []
        if not mx_records:
            return []

        lines = []

        for record in mx_records:
            lines.append(f"MX Record: {record} [DisifyTool]")

        return lines

    def _breaches(self, xposedornot):
        if not isinstance(xposedornot, dict):
            return []

        breaches = xposedornot.get("breaches") or []
        if not breaches:
            return []

        lines = []
        seen = set()

        for breach in breaches:
            names = breach if isinstance(breach, list) else [breach]

            for name in names:
                value = str(name).strip()

                if value and value not in seen:
                    seen.add(value)
                    lines.append(
                        f"{value} [XposedOrNotTool]"
                    )

        return lines

    def _accounts(self, holehe):
        if not isinstance(holehe, list):
            return []

        lines = []
        seen = set()

        for result in holehe:
            if not isinstance(result, dict):
                continue

            if result.get("exists") is not True:
                continue

            service = result.get("name") or result.get("domain")
            if not service:
                continue

            service = str(service).strip()
            key = service.casefold()

            if key in seen:
                continue

            seen.add(key)
            lines.append(f"{service} [HoleheTool]")

        return lines

    def _github(self, github):
        if not isinstance(github, dict):
            return []

        items = github.get("items") or []
        if not items:
            return []

        lines = []
        seen_accounts = set()
        seen_commits = set()

        total_count = github.get("total_count")
        if total_count is not None:
            lines.append(f"Matching Commits: {total_count} [GitHubTool]")

        for item in items:
            if not isinstance(item, dict):
                continue

            commit = item.get("commit") or {}
            author = commit.get("author") or {}
            committer = commit.get("committer") or {}

            for role in ("author", "committer"):
                account = item.get(role)

                if not isinstance(account, dict):
                    continue

                login = account.get("login")
                profile = account.get("html_url")

                if login:
                    key = login.casefold()

                    if key not in seen_accounts:
                        seen_accounts.add(key)
                        line = f"GitHub User: {login}"

                        if profile:
                            line += f" ({profile})"

                        lines.append(f"{line} [GitHubTool]")

            for role, metadata in (
                ("Author", author),
                ("Committer", committer),
            ):
                if not isinstance(metadata, dict):
                    continue

                name = metadata.get("name")
                email = metadata.get("email")

                if name:
                    key = (role, name.casefold(), (email or "").casefold())

                    if key not in seen_commits:
                        seen_commits.add(key)
                        line = f"{role}: {name}"

                        if email:
                            line += f" ({email})"

                        lines.append(f"{line} [GitHubTool]")

            url = item.get("html_url")
            if url:
                lines.append(f"Commit: {url} [GitHubTool]")

        return lines