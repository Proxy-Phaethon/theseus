# Raw input → tokens
import shlex

def tokenize(user_input):
    return shlex.split(user_input)