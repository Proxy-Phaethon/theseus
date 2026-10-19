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
    def _tool(data: dict[str, Any], name: str) -> Any:
        normalized_name = "".join(
            char for char in name.lower() if char.isalnum()
        )

        for tool_name, result in data.items():
            normalized_tool_name = "".join(
                char for char in tool_name.lower() if char.isalnum()
            )

            if normalized_name in normalized_tool_name:
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
            (
                "format",
                "Format",
                lambda v: "Valid" if v is True else "Invalid" if v is False else str(v),
            ),
            (
                "disposable",
                "Disposable",
                lambda v: "Yes" if v is True else "No" if v is False else str(v),
            ),
            (
                "role",
                "Role Account",
                lambda v: "Yes" if v is True else "No" if v is False else str(v),
            ),
            (
                "free",
                "Free Provider",
                lambda v: "Yes" if v is True else "No" if v is False else str(v),
            ),
            (
                "dns",
                "DNS",
                lambda v: "Available" if v is True else "Unavailable" if v is False else str(v),
            ),
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

        return [
            f"MX Records: {len(hosts)}",
            *(f"  {host}" for host in hosts),
        ]

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

    @classmethod
    def _accounts(
        cls,
        user_scanner: Any,
        holehe: Any,
    ) -> list[str]:
        # Normalize service names so that variants such as X (Twitter)
        # and twitter can be merged into a single finding.
        accounts: dict[str, dict[str, Any]] = {}

        def normalize_name(value: Any) -> str:
            name = str(value or "").strip().lower()

            aliases = {
                "x (twitter)": "x",
                "twitter": "x",
                "x.com": "x",
                "office365.com": "office365",
                "office.com": "office365",
                "microsoft 365": "office365",
            }

            return aliases.get(name, name)

        def get_account(name: Any) -> dict[str, Any] | None:
            if not name:
                return None

            normalized = normalize_name(name)
            if not normalized:
                return None

            if normalized not in accounts:
                accounts[normalized] = {
                    "name": str(name).strip(),
                    "sources": [],
                    "metadata": {},
                    "status": None,
                }

            return accounts[normalized]

        # User Scanner returns a list of records with status, site_name,
        # category, url, extra metadata, and sometimes media.
        scanner_records = user_scanner if isinstance(user_scanner, list) else []

        skipped_count = 0
        error_count = 0

        for result in scanner_records:
            if not isinstance(result, dict):
                continue

            status = str(result.get("status") or "").strip().lower()

            if status == "skipped":
                skipped_count += 1
                continue

            if status == "error":
                error_count += 1
                continue

            # Not Registered is a negative result, not a discovered account.
            if status != "registered":
                continue

            name = result.get("site_name")
            account = get_account(name)
            if account is None:
                continue

            if "User Scanner" not in account["sources"]:
                account["sources"].append("User Scanner")

            account["status"] = "Registered"

            for key in ("category", "url"):
                value = result.get(key)
                if value and key not in account["metadata"]:
                    account["metadata"][key] = value

            extra = result.get("extra")
            if isinstance(extra, dict):
                for key in (
                    "login",
                    "user_id",
                    "profile",
                    "account_type",
                    "matched_by",
                ):
                    value = extra.get(key)
                    if value is not None and value != "":
                        account["metadata"].setdefault(key, value)

            media = result.get("media")
            if isinstance(media, dict):
                avatar = media.get("avatar")
                if avatar:
                    account["metadata"].setdefault("avatar", avatar)

        # Holehe's positive checks complement User Scanner. Do not treat
        # rate-limited negative checks as evidence that an account is absent.
        holehe_records = holehe if isinstance(holehe, list) else []

        for result in holehe_records:
            if not isinstance(result, dict):
                continue

            if result.get("exists") is not True:
                continue

            name = result.get("name") or result.get("domain")
            account = get_account(name)
            if account is None:
                continue

            if "Holehe" not in account["sources"]:
                account["sources"].append("Holehe")

            account["status"] = account["status"] or "Positive"

        if not accounts:
            lines = []
        else:
            lines = []

            ordered_accounts = sorted(
                accounts.values(),
                key=lambda item: item["name"].lower(),
            )

            lines.append(f"Services Found: {len(ordered_accounts)}")

            for account in ordered_accounts:
                metadata = account["metadata"]
                lines.append("")
                lines.append(account["name"])

                if account["status"]:
                    lines.append(f"  Status: {account['status']}")

                category = metadata.get("category")
                if category:
                    lines.append(f"  Category: {category}")

                login = metadata.get("login")
                if login:
                    lines.append(f"  Username: {login}")

                profile = metadata.get("profile")
                if profile:
                    lines.append(f"  Profile: {profile}")

                # If there is no profile-specific URL, retain the service URL.
                elif metadata.get("url"):
                    lines.append(f"  Website: {metadata['url']}")

                user_id = metadata.get("user_id")
                if user_id is not None:
                    lines.append(f"  User ID: {user_id}")

                account_type = metadata.get("account_type")
                if account_type:
                    lines.append(f"  Account Type: {account_type}")

                matched_by = metadata.get("matched_by")
                if matched_by:
                    lines.append(f"  Evidence: {matched_by}")

                avatar = metadata.get("avatar")
                if avatar:
                    lines.append(f"  Avatar: {avatar}")

        # Summarize inconclusive checks separately. They are not account
        # findings and must not be presented as negative results.
        if skipped_count or error_count:
            if lines:
                lines.append("")
            lines.append("Inconclusive Checks")

            if skipped_count:
                lines.append(f"User Scanner Skipped: {skipped_count}")

            if error_count:
                lines.append(f"User Scanner Errors: {error_count}")

        if holehe_records:
            rate_limited = sum(
                1
                for result in holehe_records
                if isinstance(result, dict)
                and (
                    result.get("rateLimit") is True
                    or result.get("frequent_rate_limit") is True
                )
            )

            if rate_limited:
                if lines:
                    lines.append("")
                lines.append(
                    f"Holehe Rate-Limited Checks: {rate_limited} "
                    "(results may be inconclusive)"
                )

        return lines

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

                    if (
                        name.lower() == "github"
                        or email.lower().endswith("@users.noreply.github.com")
                        or email.lower() == "noreply@github.com"
                    ):
                        continue

                    identity = (name, email)
                    if identity not in identities:
                        identities.append(identity)

        if users:
            lines.append(f"GitHub Accounts Found: {len(users)}")
            for login, url in users:
                lines.append(
                    f"GitHub User: {login}" + (f" ({url})" if url else "")
                )

        if identities:
            lines.append(f"Commit Identities Found: {len(identities)}")
            for name, email in identities:
                lines.append(f"{name} ({email})")

        return lines