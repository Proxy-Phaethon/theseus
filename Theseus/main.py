# 01110100 01101000 01100101 01110011 01100101 01110101 01110011 

from tokenizer import tokenize
from parser import parse
from identifier import identify
from extractor import extract
from executor import execute
from processor import process
from responder import respond
import threading
import ui
import conversation
import random

GOODBYES = [
    "See ya.",
    "Ta-ta.",
    "Sayonara.",
    "Farewell.",
    "Until next time.",
    "Cheerio.",
    "Adieu.",
    "Ciao.",
    "So long.",
    "Safe travels.",
    "Until we meet again.",
    "The thread ends here.",
]

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
            print(random.choice(GOODBYES))
            break

        conversational_response = conversation.respond(user_input)

        if conversational_response is not None:
            print(conversational_response)
            continue

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
                result = execute(
                    operation["operation"],
                    parameters
                )

                processed_result = process(
                    operation["operation"],
                    result
                )

            finally:
                stop_event.set()
                loading_thread.join()

            response = respond(processed_result)
            print(response)

        except ValueError:
            print("sorry?")

if __name__ == "__main__":
    main()