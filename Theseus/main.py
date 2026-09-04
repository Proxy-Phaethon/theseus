from tokenizer import tokenize
from parser import parse
from identifier import identify
from extractor import extract
from executor import execute
from responder import respond


def main():
    user_input = input("> ")

    tokens = tokenize(user_input)
    instructions = parse(tokens)
    operations = identify(instructions)
    parameters = extract(operations)
    results = execute(parameters)
    response = respond(results)

    print(response)


if __name__ == "__main__":
    main()