# Execution result → user-facing response
# Execution result → user-facing response

def respond(result):
    if result is None:
        print("No results found.")
        return

    print()
    print(f"Found: {result}")