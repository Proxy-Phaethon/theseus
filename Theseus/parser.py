# Tokens → structured instructions
def parse(tokens):
    return {
        "command": tokens[0],
        "arguments": tokens[1:]
    }