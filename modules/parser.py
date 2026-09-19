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
    "until next time",
    "see you later",
    "until we meet again",
    "see ya",
}

SEARCH_TYPES = {
    "person",
    "company",
    "organization",
    "place",
    "product",
    "event",
}

def parse_search(query):
    query = query.strip()

    if query.lower().startswith("for "):
        query = query[4:].strip()

    if "," not in query:
        return None

    target_part, request_part = query.split(",", 1)

    target_tokens = target_part.split(maxsplit=1)

    if len(target_tokens) != 2:
        return None

    target_type = target_tokens[0].lower()
    target_name = target_tokens[1].strip()

    if target_type not in SEARCH_TYPES:
        return None

    if not target_name:
        return None

    request_part = request_part.strip()

    if not request_part.lower().startswith("return "):
        return None

    request_text = request_part[7:].strip()

    if not request_text:
        return None

    requests = [
        request.strip()
        for request in request_text.split(",")
        if request.strip()
    ]

    return {
        "target": {
            "type": target_type,
            "name": target_name,
        },
        "requests": requests,
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

        query = " ".join(query_tokens)

        search = parse_search(query)

        if search is None:
            return {
                "operation": "SEARCH_INVALID"
            }

        return {
            "operation": "SEARCH",
            **search
        }

    return {"operation": "UNKNOWN"}