from tokenizer import tokenize
from library.dictionary import dictionary

def parse(tokens):
    meaning = []
    for token in tokens:
        if token in dictionary:
            meaning.append(dictionary[token])
        else:
            meaning.append("unknown")
    return meaning