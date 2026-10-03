class UsernameResponder:
    def respond(self, results):
        data = {
            tool_name: result
            for tool_name, result in results
        }

        accounts = data.get("WhatsMyNameTool", [])

        if not accounts:
            return "No accounts found."

        lines = []

        for account in accounts:
            site = account.get("site")
            category = account.get("category")
            url = account.get("url")

            if not site or not url:
                continue

            lines.append(site)

            if category:
                lines.append(f"  Category: {category}")

            lines.append(f"  URL: {url}")
            lines.append("")

        return "\n".join(lines).rstrip()