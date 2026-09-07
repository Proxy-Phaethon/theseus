from modules.tokenizer import tokenize
from modules.parser import parse
from modules.commands.search import search
from modules.responder import respond, start_thinking

import random

FAREWELLS = [
    "Bye.",
    "Ta-ta",
    "Sayonara",
    "Adios",
    "Ciao",
    "Farewell",
    "Until next time",
    "See you later",
    "Until we meet again",
    "See ya",
]

GREETINGS = [
    "Hey",
    "What's Up",
    "What can I do for you?",
]

def main():
    print("Hey.")

    while True:
        command = input("> ")

        tokens = tokenize(command)
        parsed = parse(tokens)

        if parsed["operation"] == "GREETING":
            print(random.choice(GREETINGS))

        elif parsed["operation"] == "FAREWELL":
            print(random.choice(FAREWELLS))
            break

        elif parsed["operation"] == "SEARCH":
            stop_thinking, thinking_thread = start_thinking()

            try:
                results = search(parsed["query"])
            finally:
                stop_thinking.set()
                thinking_thread.join()

            respond(results)

        else:
            print("sorry?")

if __name__ == "__main__":
    main()