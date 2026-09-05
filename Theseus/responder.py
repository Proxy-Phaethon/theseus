# Execution result → user-facing response

def respond(results):
    if results is None:
        return "No results found."

    if not results:
        return "No usable sources found."

    response = []

    for result in results:
        response.append(
            f"Found: {result['title']}\n"
            f"{result['description']}\n"
            f"Source: {result['url']}"
        )

    return "\n\n".join(response)