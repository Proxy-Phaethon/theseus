class UsernameResponder:
    def respond(self, results):
        if not results:
            return "No accounts found."

        lines = []

        for result in results:
            site = result.get("site")
            category = result.get("category")
            url = result.get("url")

            if not site or not url:
                continue

            lines.append(site)

            if category:
                lines.append(f"  Category: {category}")

            lines.append(f"  URL: {url}")
            lines.append("")

        return "\n".join(lines).rstrip()