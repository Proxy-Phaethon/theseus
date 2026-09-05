# Execution result → user-facing response

def respond(result):
    if result is None:
        return "No results found."

    summary = result.get("summary")
    sources = result.get("sources", [])

    response = []

    if summary:
        response.append(summary)

    if sources:
        response.append("")
        response.append("Sources:")

        for index, source in enumerate(sources, start=1):
            title = source.get("title")
            url = source.get("url")

            if title and url:
                response.append(f"[{index}] {title}")
                response.append(f"    {url}")

            elif url:
                response.append(f"[{index}] {url}")

    return "\n".join(response)