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

        xposedornot = data.get("XposedOrNotTool", {})
        disify = data.get("DisifyTool", {})

        sections = []

        identity = self._identity(xposedornot, disify)
        if identity:
            sections.append(("Email Identity", identity))

        infrastructure = self._infrastructure(disify)
        if infrastructure:
            sections.append(("Email Infrastructure", infrastructure))

        breaches = self._breaches(xposedornot)
        if breaches:
            sections.append(("Breach Exposure", breaches))

        return self._format_sections(sections)

    def _identity(self, xposedornot, disify):
        lines = []

        email = xposedornot.get("email")
        if email:
            lines.append(f"Email: {email}")

        domain = disify.get("domain")
        if domain:
            lines.append(f"Domain: {domain}")

        domain_info = disify.get("domain_info", {})

        tld = domain_info.get("tld")
        if tld:
            lines.append(f"TLD: .{tld}")

        is_subdomain = domain_info.get("is_subdomain")
        if is_subdomain is not None:
            lines.append(
                f"Subdomain: {'Yes' if is_subdomain else 'No'}"
            )

        format_valid = disify.get("format")
        if format_valid is not None:
            lines.append(
                f"Format: {'Valid' if format_valid else 'Invalid'}"
            )

        disposable = disify.get("disposable")
        if disposable is not None:
            lines.append(
                f"Disposable: {'Yes' if disposable else 'No'}"
            )

        role = disify.get("role")
        if role is not None:
            lines.append(
                f"Role Account: {'Yes' if role else 'No'}"
            )

        free = disify.get("free")
        if free is not None:
            lines.append(
                f"Free Provider: {'Yes' if free else 'No'}"
            )

        dns = disify.get("dns")
        if dns is not None:
            lines.append(
                f"DNS: {'Available' if dns else 'Not detected'}"
            )

        whitelist = disify.get("whitelist")
        if whitelist is not None:
            lines.append(
                f"Whitelist: {'Yes' if whitelist else 'No'}"
            )

        confidence = disify.get("confidence")
        if confidence is not None:
            lines.append(f"Confidence: {confidence}")

        return lines

    def _infrastructure(self, disify):
        mx_records = disify.get("mx_info", [])

        if not mx_records:
            return []

        lines = ["MX Records:"]

        for record in mx_records:
            lines.append(f"  {record}")

        return lines

    def _breaches(self, xposedornot):
        breaches = xposedornot.get("breaches", [])

        if not breaches:
            return []

        lines = ["Breaches:"]

        for breach in breaches:
            if isinstance(breach, list):
                for name in breach:
                    lines.append(f"  {name}")
            else:
                lines.append(f"  {breach}")

        return lines

    @staticmethod
    def _format_sections(sections):
        output = []

        for title, lines in sections:
            output.append(title)

            for line in lines:
                output.append(f"  {line}")

            output.append("")

        return "\n".join(output).rstrip()