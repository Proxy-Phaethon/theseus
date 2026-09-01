from tokenizer import tokenize

dictionary = {
    "hi": "greeting",
    "hello": "greeting",
    "im": "identity",
    "i'm": "identity",
    "z": "name",
    "bob": "name"
}

def parse(tokens):
    meaning = []
    for token in tokens:
        if token in dictionary:
            meaning.append(dictionary[token])
        else:
            meaning.append("unknown")
    return meaning
