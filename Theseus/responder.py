# Execution result → user-facing response
import time

def respond(result):
    print()
    print("Searching", end="", flush=True)

    for _ in range(3):
        time.sleep(0.3)
        print(".", end="", flush=True)

    print()

    if result is None:
        print("No results found.")
        return

    print()
    print(f"Found: {result}")