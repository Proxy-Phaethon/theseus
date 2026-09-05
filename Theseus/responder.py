# Execution result → user-facing response

def respond(results):
    if results is None:
        return "No results found."

    if not results:
        return "No usable sources found."

    response = []

    for result in results:
        entry = f"Found: {result['title']}"

        if result["description"]:
            entry += f"\n{result['description']}"

        entry += f"\nSource: {result['url']}"

        response.append(entry)

    return "\n\n".join(response)