# Raw input → tokens
def parse(tokens):
    if not tokens:
        return None

    return {
        "command": tokens[0],
        "arguments": tokens[1:]
    }