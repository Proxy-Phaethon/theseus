import itertools
import sys
import threading
import time

def thinking_animation(stop_event):
    frames = itertools.cycle([".", "..", "..."])

    while not stop_event.is_set():
        frame = next(frames)
        sys.stdout.write(f"\rTheseus is thinking{frame}   ")
        sys.stdout.flush()
        time.sleep(0.4)

    sys.stdout.write("\r" + " " * 30 + "\r")
    sys.stdout.flush()

def start_thinking():
    stop_event = threading.Event()

    thread = threading.Thread(
        target=thinking_animation,
        args=(stop_event,),
        daemon=True,
    )

    thread.start()

    return stop_event, thread

def respond(results):
    if not results:
        print("No results found.")
        return

    for index, result in enumerate(results, start=1):
        title = result.get("title", "Untitled")
        url = result.get("url", "")
        content = result.get("content", "")

        print(f"{index}. {title}")
        print(f"   {url}")

        if content:
            print(f"   {content}")

        print()