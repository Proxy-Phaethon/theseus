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
    "MISSING_TYPE": [
        "Be more specific. What exactly is that?",
        "What kind of thing are we looking for?",
        "I need a target type before we begin.",
        "Person? Company? Place? Give me something to work with.",
    ],

    "INVALID_TYPE": [
        "I don't recognize that as a target type.",
        "I'm not sure what kind of thing that is.",
        "That doesn't look like a target type I know.",
        "Try giving me something like person, company, place, or event.",
    ],

    "MISSING_REQUEST": [
        "You found the target. Now tell me what you want to know.",
        "Target acquired. What information are you after?",
        "I know who we're looking for. What should I find out?",
        "You've given me the target. Now give me the question.",
        "Fine. I have the target. What do you want from it?",
    ],

    "MISSING_RETURN": [
        "And what would you like me to find about it?",
        "You've identified the target. Now tell me what information you want.",
        "What should I find out about it?",
        "Target noted. What information are we after?",
    ],
}

def random_response(responses, last_response=None):
    choices = [
        response
        for response in responses
        if response != last_response
    ]

    return random.choice(choices)

def main():
    print("Hey.")

    last_search_response = None

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
            error = parsed["error"]

            response = random_response(
                SEARCH_ERRORS[error],
                last_search_response
            )

            print(response)
            last_search_response = response

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