# animations ehe
import sys
import time
import threading

def loading(stop_event):
    frames = ["|", "/", "-", "\\"]

    index = 0

    while not stop_event.is_set():
        sys.stdout.write(f"\rTheseus is searching {frames[index]}")
        sys.stdout.flush()

        index = (index + 1) % len(frames)

        time.sleep(0.1)

    sys.stdout.write("\r" + " " * 30 + "\r")
    sys.stdout.flush()


THESEUS = [
    "██▀▀▀▓▓▀▀▀██ ▀▓▓▀    ▀▓█▀   ▀▓▓▀▀▀▀▀▓▒▄  ▀▓▓▀▀▀▀▀█▓▄   ▀▓▓▀▀▀▀▀▓▒▄  ▀▓▓▀   ▀▓▓▀ ▀▓▓▀▀▀▀▀█▓▄",
    "██   ▒▓  ▄▀   ▒▓      ▒▓     ▒░      ▀▀   ▒▓      ▒▓    ▒░      ▀▀   ▓▒     ▓▒   ▒▓      ▒▓",
    "     ▒▒ ▐     ▒▒      ▓▒     ░▀  ▄▄       ▒▒▄           ░▀  ▄▄       ▒▒     ▒░   ▒▒▄",
    "     ▒░  ▀    ▒░▀▀▀▀▀▓▒▒    ▄▄▀▀▀  ▄▄▄     ▀▀▀▀▀▀▓▒▄   ▄▄▀▀▀  ▄▄▄    ▒░     ░░    ▀▀▀▀▀▀▓▒▄",
    "     ░░       ░░      ░░  ▄▀ ▄░     ▀█░    ▄█▀    ░░ ▄▀ ▄░     ▀█░   ░░     █░    ▄█▀    ░░",
    "     ░░       ░░      ░█   ▀ ██      ██▌  ░░▌     ░█  ▀ ██      ██▌  █░     ░█   ░░▌     ░█",
    "    ▄██      ▄██▄    ▄██▄   ▄██▄▄▄▄▄██▀  ▄██▄▄▄▄▄█▀    ▄██▄▄▄▄▄██▀  ▄██▄▄▄▄██▀  ▄██▄▄▄▄▄█▀",
]
