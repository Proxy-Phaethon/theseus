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

    if not query:
        return {
            "error": "MISSING_TYPE"
        }

    target_tokens = query.split(maxsplit=1)

    target_type = target_tokens[0].lower()

    if target_type not in SEARCH_TYPES:
        return {
            "error": "INVALID_TARGET_TYPE",
            "target_type": target_type,
        }

    if len(target_tokens) == 1:
        return {
            "error": "MISSING_TARGET",
            "target_type": target_type,
        }

    remainder = target_tokens[1].strip()

    if "," not in remainder:
        return {
            "error": "MISSING_RETURN",
            "target_type": target_type,
            "target_name": remainder,
        }

    target_name, request_part = remainder.split(",", 1)

    target_name = target_name.strip()
    request_part = request_part.strip()

    if not target_name:
        return {
            "error": "MISSING_TARGET",
            "target_type": target_type,
        }

    if not request_part.lower().startswith("return"):
        return {
            "error": "MISSING_RETURN",
            "target_type": target_type,
            "target_name": target_name,
        }

    request_text = request_part[6:].strip()

    if not request_text:
        return {
            "error": "MISSING_REQUEST",
            "target_type": target_type,
            "target_name": target_name,
        }

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
        query = " ".join(tokens[1:])

        search = parse_search(query)

        if "error" in search:
            return {
                "operation": "SEARCH_INVALID",
                **search
            }

        return {
            "operation": "SEARCH",
            **search
        }

    return {"operation": "UNKNOWN"}