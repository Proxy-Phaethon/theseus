from typing import Any

from core.identifier import Entity

class DomainResponder:
    def respond(
        self,
        entity: Entity,
        results: list[tuple[str, Any]],
    ) -> str:
        data = {
            tool_name: result
            for tool_name, result in results
        }

        ldns = data.get("LDNSTool", {})
        rdap = data.get("RDAPTool", {})

        sections = []

        identity = self._identity(ldns, rdap)
        if identity:
            sections.append(("Domain Identity", identity))

        web = self._web_presence(ldns)
        if web:
            sections.append(("Web Presence", web))

        security = self._security(ldns)
        if security:
            sections.append(("Security", security))

        registration = self._registration(rdap)
        if registration:
            sections.append(("Registration", registration))

        status = self._domain_status(rdap)
        if status:
            sections.append(("Domain Status", status))

        nameservers = self._nameservers(rdap)
        if nameservers:
            sections.append(("Nameservers", nameservers))

        dns_security = self._dns_security(rdap)
        if dns_security:
            sections.append(("DNS Security", dns_security))

        return self._format_sections(sections)

    def _identity(self, ldns, rdap):
        lines = []

        domain = rdap.get("ldhName") or ldns.get("domain")

        if domain:
            lines.append(f"Domain: {domain.lower()}")

        info = ldns.get("info", {})

        url = info.get("url")
        if url:
            lines.append(f"Canonical URL: {url}")

        redirects = ldns.get("redirects", {})

        if redirects:
            original = redirects.get("originalUrl")
            final = redirects.get("finalUrl")

            if original and final and original != final:
                lines.append(
                    f"Redirect: {original} → {final}"
                )

        return lines

    def _web_presence(self, ldns):
        info = ldns.get("info", {})

        if not info:
            return []

        lines = []

        status = info.get("status")
        status_text = info.get("statusText")

        if status is not None:
            value = str(status)

            if status_text:
                value += f" {status_text}"

            lines.append(f"Status: {value}")

        server = info.get("server")
        if server:
            lines.append(f"Server: {server}")

        response_time = info.get("responseTime")
        if response_time is not None:
            lines.append(
                f"Response Time: {response_time} ms"
            )

        content_type = info.get("contentType")
        if content_type:
            lines.append(f"Content Type: {content_type}")

        content_length = info.get("contentLength")
        if content_length is not None:
            lines.append(
                f"Content Length: {content_length} bytes"
            )

        redirects = ldns.get("redirects", {})

        total_time = redirects.get("totalTime")
        if total_time is not None:
            lines.append(
                f"Total Request Time: {total_time} ms"
            )

        return lines

    def _security(self, ldns):
        lines = []

        alt_svc = ldns.get("altSvc", {})

        if "http3" in alt_svc:
            lines.append(
                "HTTP/3: "
                f"{'Supported' if alt_svc['http3'] else 'Not detected'}"
            )

        headers = ldns.get("securityHeaders", [])

        if headers:
            lines.append("Security Headers:")

            for header in headers:
                key = header.get("key")
                present = header.get("present")

                if not key:
                    continue

                state = "Present" if present else "Missing"
                lines.append(f"  {key}: {state}")

        return lines

    def _registration(self, rdap):
        lines = []

        entities = rdap.get("entities", [])

        for entity in entities:
            roles = entity.get("roles", [])

            if "registrar" not in roles:
                continue

            vcard = entity.get("vcardArray", [])

            name = self._vcard_name(vcard)

            if name:
                lines.append(f"Registrar: {name}")

            break

        events = rdap.get("events", [])

        event_names = {
            "registration": "Registration Date",
            "expiration": "Expiration Date",
            "last changed": "Last Changed",
        }

        for event in events:
            action = event.get("eventAction")
            date = event.get("eventDate")

            label = event_names.get(action)

            if label and date:
                lines.append(f"{label}: {date}")

        return lines

    def _domain_status(self, rdap):
        statuses = rdap.get("status", [])

        if not statuses:
            return []

        lines = ["Statuses:"]

        for status in statuses:
            lines.append(f"  {status}")

        return lines

    def _nameservers(self, rdap):
        nameservers = rdap.get("nameservers", [])

        if not nameservers:
            return []

        lines = ["Nameservers:"]

        for nameserver in nameservers:
            name = nameserver.get("ldhName")

            if name:
                lines.append(f"  {name.lower()}")

        return lines

    def _dns_security(self, rdap):
        secure_dns = rdap.get("secureDNS")

        if not secure_dns:
            return []

        delegation_signed = secure_dns.get("delegationSigned")

        if delegation_signed is None:
            return []

        return [
            "DNSSEC: "
            f"{'Enabled' if delegation_signed else 'Not enabled'}"
        ]

    @staticmethod
    def _vcard_name(vcard):
        if not vcard or len(vcard) < 2:
            return None

        properties = vcard[1]

        for property_data in properties:
            if len(property_data) < 4:
                continue

            if property_data[0] == "fn":
                return property_data[3]

        return None

    @staticmethod
    def _format_sections(sections):
        output = []

        for title, lines in sections:
            output.append(title)

            for line in lines:
                output.append(f"  {line}")

            output.append("")

        return "\n".join(output).rstrip()