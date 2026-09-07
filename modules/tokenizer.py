import shlex

def tokenize(command):
    return shlex.split(command)