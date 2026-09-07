GREETINGS = {
    "hi",
    "hello",
    "hey",
    "greetings",
}

FAREWELLS = {
    "bye",
    "goodbye",
    "farewell",
    "sayonara",
    "q",
    "quit",
    "end convo",
    "end",
    "end conversation",
    "ta-ta",
    "adios",
    "ciao",
    "farewell",
    "until next time",
    "see you later",
    "until we meet again",
    "see ya",
}

def parse(tokens):
    if not tokens:
        return {"operation": "UNKNOWN"}

    command = tokens[0].lower()

    if command in GREETINGS:
        return {"operation": "GREETING"}

    if command in FAREWELLS:
        return {"operation": "FAREWELL"}

    if command == "search":
        query_tokens = tokens[1:]

        if query_tokens and query_tokens[0].lower() == "for":
            query_tokens = query_tokens[1:]

        return {
            "operation": "SEARCH",
            "query": " ".join(query_tokens)
        }

    return {"operation": "UNKNOWN"}