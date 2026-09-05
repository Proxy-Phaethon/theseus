# Execution result → user-facing response
def respond(result):
    if not result:
        return "No results found."

    paragraph = result.get("paragraph")
    sources = result.get("sources", [])

    response = []

    if paragraph:
        response.append(paragraph)

    if sources:
        response.append("")
        response.append("Sources:")

        for index, source in enumerate(sources, start=1):
            response.append(f"[{index}] {source}")

    return "\n".join(response)