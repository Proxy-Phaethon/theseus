from modules.tokenizer import tokenize
from modules.parser import parse
from modules.commands.search import search_all
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
        "You've given me a name, but not what it belongs to.",
        "I need to know what I'm looking at first.",
    ],

    "INVALID_TARGET_TYPE": [
        "'{target_type}'? Seriously?",
        "I don't recognize '{target_type}' as a target type.",
        "We're conducting an investigation, not whatever '{target_type}' is.",
        "Please give me an actual target type, not '{target_type}'.",
        "I have no idea what '{target_type}' is supposed to mean.",
        "Since when is '{target_type}' a target type?",
        "I'm going to need a better category than '{target_type}'.",
        "'{target_type}' is certainly a choice.",
    ],

    "MISSING_TARGET": [
        "You've given me the type. Where's the target?",
        "I know what we're looking for. Now tell me who or what it is.",
        "Target type noted. Target missing.",
        "You forgot the actual target.",
        "Person, company, place... excellent. Which one?",
    ],

    "MISSING_REQUEST": [
        "You've given me {target_type} '{target_name}'. Now what do you want to know?",
        "I have {target_type} '{target_name}'. What's the objective?",
        "Target acquired: {target_name}. What information are you after?",
    ],

    "MISSING_RETURN": [
        "And what would you like me to find about it?",
        "You've identified the target. Now tell me what information you want.",
        "What should I find out about it?",
        "Target noted. What information are we after?",
        "You've given me someone to investigate. Give me something to investigate.",
        "What exactly am I supposed to extract from this?",
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

            response = response.format(
                target_type=parsed.get("target_type", ""),
                target_name=parsed.get("target_name", "")
            )

            print(response)
            last_search_response = response

        elif parsed["operation"] == "SEARCH":
            stop_event, thread = start_thinking()

            try:
                result = search_all(parsed)
            finally:
                stop_event.set()
                thread.join()

            respond(result)

        else:
            print("sorry?")

if __name__ == "__main__":
    main()