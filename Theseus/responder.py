# Execution result → user-facing response

def respond(result):
    if not result:
        return "No results found."

    query = result.get("query", "")
    matches = result.get("matches", [])

    if not matches:
        return "No relevant evidence found."

    response = []

    if query:
        response.append(query.capitalize())
        response.append("")

    for match in matches:
        text = match.get("text")

        if not text:
            continue

        response.append(text)

    sources = []
    seen = set()

    for match in matches:
        source = match.get("source")

        if source and source not in seen:
            sources.append(source)
            seen.add(source)

    if sources:
        response.append("")
        response.append("Sources:")

        for index, source in enumerate(sources, start=1):
            response.append(f"[{index}] {source}")

    return "\n".join(response)