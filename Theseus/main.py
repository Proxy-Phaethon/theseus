# 01110100 01101000 01100101 01110011 01100101 01110101 01110011 

from tokenizer import tokenize
from parser import parse
from identifier import identify
from extractor import extract
from executor import execute
from responder import respond
import threading
import ui

EXIT_COMMANDS = {
    "bye",
    "goodbye",
    "exit",
    "quit",
    "q",
    "see ya",
    "farewell",
    "adieu",
    "ciao",
    "sayonara",
}

def main():
    print("Hey.")
    while True:
        user_input = input("> ")
        if not user_input.strip():
            continue

        if user_input.strip().lower() in EXIT_COMMANDS:
            print("See ya.")
            break

        try:
            tokens = tokenize(user_input)
            instruction = parse(tokens)
            operation = identify(instruction)
            parameters = extract(operation)

            stop_event = threading.Event()

            loading_thread = threading.Thread(
                target=ui.loading,
                args=(stop_event,)
            )

            loading_thread.start()

            try:
                result = execute(operation["operation"], parameters)

            finally:
                stop_event.set()
                loading_thread.join()

            response = respond(result)
            print(response)

        except ValueError:
            print("sorry?")

if __name__ == "__main__":
    main()