import itertools
import sys
import threading
import time

def thinking_animation(stop_event):
    frames = itertools.cycle([".", "..", "..."])

    while not stop_event.is_set():
        frame = next(frames)

        sys.stdout.write(
            f"\rSearching{frame}   "
        )
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

def respond(result):
    if not result:
        print("I couldn't find a reliable answer.")
        return

    answers = result.get("answers", [])

    if not answers:
        print("Error.")
        return

    for answer in answers:
        print(answer["answer"])