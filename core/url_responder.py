class URLResponder:
    def respond(self, results):
        data = {
            tool_name: result
            for tool_name, result in results
        }

        http = data.get("HTTPTool", {})
        dns = data.get("DNSTool", {})

        sections = []

        http_section = self._http(http)
        if http_section:
            sections.append(("HTTP", http_section))

        redirect_section = self._redirects(http)
        if redirect_section:
            sections.append(("Redirects", redirect_section))

        dns_section = self._dns(dns)
        if dns_section:
            sections.append(("DNS", dns_section))

        return self._format_sections(sections)

    def _http(self, http):
        lines = []

        requested_url = http.get("requested_url")
        if requested_url:
            lines.append(f"Requested URL: {requested_url}")

        final_url = http.get("final_url")
        if final_url:
            lines.append(f"Final URL: {final_url}")

        status_code = http.get("status_code")
        reason = http.get("reason")

        if status_code is not None:
            if reason:
                lines.append(f"Status: {status_code} {reason}")
            else:
                lines.append(f"Status: {status_code}")

        content_type = http.get("content_type")
        if content_type:
            lines.append(f"Content Type: {content_type}")

        content_length = http.get("content_length")
        if content_length is not None:
            lines.append(f"Response Size: {content_length} bytes")

        response_time = http.get("response_time_ms")
        if response_time is not None:
            lines.append(f"Response Time: {response_time} ms")

        return lines

    def _redirects(self, http):
        redirects = http.get("redirects", [])

        if not redirects:
            return []

        lines = ["Chain:"]

        for redirect in redirects:
            url = redirect.get("url")
            status_code = redirect.get("status_code")
            location = redirect.get("location")

            if not url:
                continue

            if status_code is not None and location:
                lines.append(
                    f"  {url} → {location} ({status_code})"
                )
            elif status_code is not None:
                lines.append(
                    f"  {url} ({status_code})"
                )
            else:
                lines.append(f"  {url}")

        return lines

    def _dns(self, dns):
        records = dns.get("records", {})

        if not records:
            return []

        lines = []

        for record_type in (
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "TXT",
        ):
            values = records.get(record_type, [])

            if not values:
                continue

            lines.append(f"{record_type}:")

            for value in values:
                lines.append(f"  {value}")

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