# Instructions → operation(s)
def identify(instruction):
    return {
        "operation": instruction["command"],
        "parameters": instruction["arguments"]
    }