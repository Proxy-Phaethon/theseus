class EmailResponder:
    def respond(self, results):
        data = {
            tool_name: result
            for tool_name, result in results
        }

        xposedornot = data.get("XposedOrNotTool", {})

        sections = []

        identity = self._identity(xposedornot)
        if identity:
            sections.append(("Email Identity", identity))

        breaches = self._breaches(xposedornot)
        if breaches:
            sections.append(("Breach Exposure", breaches))

        return self._format_sections(sections)

    def _identity(self, data):
        lines = []

        email = data.get("email")

        if email:
            lines.append(f"Email: {email}")

        return lines

    def _breaches(self, data):
        breaches = data.get("breaches", [])

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