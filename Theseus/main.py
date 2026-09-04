from tokenizer import tokenize
from parser import parse
from identifier import identify
from extractor import extract
from executor import execute
from responder import respond


def main():
    user_input = input("> ")

    tokens = tokenize(user_input)
    instruction = parse(tokens)
    operation = identify(instruction)
    parameters = extract(operation)

    result = execute(operation["operation"], parameters)
    #need to add processor here
    respond(result)

if __name__ == "__main__":
    main()