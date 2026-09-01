from tokenizer import tokenize

dictionary = {
    "hi": "greeting",
    "hello": "greeting",
    "im": "identity",
    "i'm": "identity",
    "i": "identity",
    "z": "name",
    "bob": "name",
    "what's": "question",
    "whats": "question",
    "up": "question",
}

def parse(tokens):
    meaning = []
    for token in tokens:
        if token in dictionary:
            meaning.append(dictionary[token])
        else:
            meaning.append("unknown")
    return meaning
