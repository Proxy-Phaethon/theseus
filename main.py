from modules.tokenizer import tokenize
from modules.parser import parse
from modules.commands.search import (
    search,
    understand_query,
    recognize_answer,
    rank_answers
)
from modules.responder import respond

import random

FAREWELLS = [
    "Bye.",
    "Ta-ta",
    "Sayonara",
    "Adios",
    "Ciao",
    "Farewell",
    "Until next time",
    "Until we meet again",
    "See you later",
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

            query_structure = understand_query(query)

            answer_type = query_structure["answer_type"]
            predicate = query_structure["predicate"]

            relation_map = {
                "found": "FOUNDED",
                "founded": "FOUNDED",
                "invent": "INVENTED",
                "invented": "INVENTED",
                "originate": "ORIGIN",
                "originated": "ORIGIN",
                "live": "POPULATION",
                "population": "POPULATION",
                "be": "CEO",
            }

            relation = relation_map.get(
                predicate.lower() if predicate else "",
                "UNKNOWN"
            )

            results = search(query)

            candidates = recognize_answer(
                query,
                results,
                answer_type,
                relation
            )

            answer = rank_answers(candidates)

            respond(answer)

        else:
            print("sorry?")

if __name__ == "__main__":
    main()