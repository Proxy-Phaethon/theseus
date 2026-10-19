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

        accounts = self._accounts(holehe)
        if accounts:
            sections.append((
                "Possible Account Registrations "
                "(rate-limited checks may be unreliable)",
                accounts,
            ))

        footprint = self._github(github)
        if footprint:
            sections.append(("Public Code Footprint", footprint))

        return self._format_sections(sections)

    @staticmethod
    def _tool(data: dict[str, Any], name: str) -> Any:
        for tool_name, result in data.items():
            if name in tool_name:
                return result
        return {}

    @staticmethod
    def _format_sections(
        sections: list[tuple[str, list[str]]],
    ) -> str:
        output = []

        for heading, lines in sections:
            if not lines:
                continue

            output.append(heading)
            output.extend(f"  {line}" for line in lines)
            output.append("")

        return "\n".join(output).rstrip()

    @staticmethod
    def _identity(email: str, data: Any) -> list[str]:
        if not isinstance(data, dict):
            data = {}

        lines = [f"Address: {email}"]

        domain = data.get("domain")
        if domain:
            lines.append(f"Domain: {domain}")

        tld = data.get("tld")
        if not tld and isinstance(domain, str) and "." in domain:
            tld = "." + domain.rsplit(".", 1)[-1]

        if tld:
            lines.append(f"TLD: {tld}")

        fields = [
            ("format", "Format", lambda v: "Valid" if v is True else "Invalid" if v is False else str(v)),
            ("disposable", "Disposable", lambda v: "Yes" if v is True else "No" if v is False else str(v)),
            ("role", "Role Account", lambda v: "Yes" if v is True else "No" if v is False else str(v)),
            ("free", "Free Provider", lambda v: "Yes" if v is True else "No" if v is False else str(v)),
            ("dns", "DNS", lambda v: "Available" if v is True else "Unavailable" if v is False else str(v)),
        ]

        for key, label, formatter in fields:
            value = data.get(key)
            if value is not None:
                lines.append(f"{label}: {formatter(value)}")

        return lines

    @staticmethod
    def _infrastructure(data: Any) -> list[str]:
        if not isinstance(data, dict):
            return []

        mx_info = data.get("mx_info")
        if not mx_info:
            return []

        if isinstance(mx_info, dict):
            records = mx_info.get("records", mx_info.get("mx", []))
        else:
            records = mx_info

        if isinstance(records, str):
            records = [records]

        if not isinstance(records, (list, tuple)):
            return []

        hosts = []

        for record in records:
            if isinstance(record, str):
                host = record
            elif isinstance(record, dict):
                host = (
                    record.get("exchange")
                    or record.get("host")
                    or record.get("hostname")
                    or record.get("target")
                    or record.get("name")
                )
            else:
                host = None

            if host and str(host) not in hosts:
                hosts.append(str(host))

        if not hosts:
            return []

        lines = [f"MX Records: {len(hosts)}"]
        lines.extend(f"  {host}" for host in hosts)
        return lines

    @staticmethod
    def _breaches(data: Any) -> list[str]:
        if not isinstance(data, dict):
            return []

        breaches = data.get("breaches", [])
        names = []

        def collect(value: Any) -> None:
            if isinstance(value, str):
                if value not in names:
                    names.append(value)
            elif isinstance(value, dict):
                name = value.get("name") or value.get("Name")
                if name and name not in names:
                    names.append(str(name))
            elif isinstance(value, (list, tuple)):
                for item in value:
                    collect(item)

        collect(breaches)

        if not names:
            return []

        return [
            f"Breaches Found: {len(names)}",
            *(f"Breach: {name}" for name in names),
        ]

    @staticmethod
    def _accounts(data: Any) -> list[str]:
        if not isinstance(data, list):
            return []

        accounts = []

        for result in data:
            if not isinstance(result, dict):
                continue

            if result.get("exists") is not True:
                continue

            name = result.get("name") or result.get("domain")
            if name and name not in accounts:
                accounts.append(str(name))

        return sorted(accounts, key=str.lower)

    @staticmethod
    def _github(data: Any) -> list[str]:
        if not isinstance(data, dict):
            return []

        items = data.get("items", [])
        total_count = data.get("total_count")
        lines = []

        if isinstance(total_count, int):
            lines.append(f"Matching Commits: {total_count}")

        users = []
        identities = []

        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue

                account = item.get("author")
                if isinstance(account, dict):
                    login = account.get("login")
                    url = account.get("html_url")

                    if (
                        login
                        and not login.lower().endswith("[bot]")
                        and login.lower() not in {"web-flow"}
                    ):
                        entry = (login, url)
                        if entry not in users:
                            users.append(entry)

                commit = item.get("commit", {})
                if not isinstance(commit, dict):
                    continue

                for key in ("author", "committer"):
                    person = commit.get(key)
                    if not isinstance(person, dict):
                        continue

                    name = person.get("name")
                    email = person.get("email")

                    if not name or not email:
                        continue

                    if name.lower() == "github" or email.lower().endswith(
                        "@users.noreply.github.com"
                    ) or email.lower() == "noreply@github.com":
                        continue

                    identity = (name, email)
                    if identity not in identities:
                        identities.append(identity)

        if users:
            lines.append(f"GitHub Accounts Found: {len(users)}")
            for login, url in users:
                lines.append(f"GitHub User: {login}" + (f" ({url})" if url else ""))

        if identities:
            lines.append(f"Commit Identities Found: {len(identities)}")
            for name, email in identities:
                lines.append(f"{name} ({email})")

        return lines