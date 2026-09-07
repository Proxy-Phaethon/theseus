from modules.tokenizer import tokenize
from modules.parser import parse
from modules.commands.search import (
    search,
    classify_query,
    recognize_answer,
    rank_answers
)
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

            answer_type, relation = classify_query(query)

            stop_thinking, thinking_thread = start_thinking()

            try:
                results = search(query)

                candidates = recognize_answer(
                    query,
                    results,
                    answer_type,
                    relation
                )

                answer = rank_answers(candidates)

            finally:
                stop_thinking.set()
                thinking_thread.join()

            respond(answer)

        else:
            print("sorry?")

if __name__ == "__main__":
    main()