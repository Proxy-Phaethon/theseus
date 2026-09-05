# Execution result → user-facing response

def respond(result):
    if result is None:
        return "No results found."

    title = result.get("title")
    paragraph = result.get("paragraph")
    sources = result.get("sources", [])

    response = []

    if title:
        response.append(title)

    if paragraph:
        response.append("")
        response.append(paragraph)

    if sources:
        response.append("")
        response.append("Sources:")

        for index, source in enumerate(sources, start=1):
            source_title = source.get("title")
            url = source.get("url")

            if source_title and url:
                response.append(f"[{index}] {source_title}")
                response.append(f"    {url}")

            elif url:
                response.append(f"[{index}] {url}")

    return "\n".join(response)