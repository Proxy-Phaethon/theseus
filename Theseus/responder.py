# Execution result → user-facing response

def respond(result):
    if result is None:
        return "No results found."

    return f"Found: {result}"