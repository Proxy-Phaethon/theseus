from modules.tokenizer import tokenize
from modules.parser import parse
from modules.commands.search import answer_query
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
            query = parsed["query"]

            stop_event, thread = start_thinking()

            try:
                answer = answer_query(query)
            finally:
                stop_event.set()
                thread.join()

            respond(answer)

        else:
            print("sorry?")

if __name__ == "__main__":
    main()