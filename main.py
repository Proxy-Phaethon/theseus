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

SEARCH_ERRORS = {
    "MISSING_TYPE":
        "Be more specific. What exactly is that thing?",

    "INVALID_TYPE":
        "I need to know what kind of thing I'm looking for.",

    "MISSING_TARGET":
        "You forgot to tell me what I'm actually looking for.",

    "MISSING_RETURN":
        "And what would you like me to find about it?",

    "MISSING_REQUEST":
        "Find what, exactly?",

}

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

        elif parsed["operation"] == "SEARCH_INVALID":
            print(
                SEARCH_ERRORS.get(
                    parsed["error"],
                    "You're going to have to give me a little more to work with."
                )
            )

        elif parsed["operation"] == "SEARCH":
            stop_event, thread = start_thinking()

            try:
                answer = answer_query(parsed)
            finally:
                stop_event.set()
                thread.join()

            respond(answer)

        else:
            print("sorry?")

if __name__ == "__main__":
    main()