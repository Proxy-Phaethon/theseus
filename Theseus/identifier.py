# Instructions → operation(s)
OPERATIONS = {
    "search": "SEARCH"
}

def identify(instruction):
    command = instruction["command"].lower()

    if command not in OPERATIONS:
        raise ValueError(f"Unknown command: {command}")

    return {
        "operation": OPERATIONS[command],
        "parameters": instruction["arguments"]
    }