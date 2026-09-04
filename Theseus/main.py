from tokenizer import tokenize
from parser import parse
from identifier import identify
from extractor import extract
from executor import execute
from responder import respond


def main():
    user_input = input("> ")

    tokens = tokenize(user_input)
    print("Tokens:", tokens)

    instruction = parse(tokens)
    print("Instructions:", instruction)

    operation = identify(instruction)
    print("Operations:", operation)

    parameters = extract(operation)
    print("Parameters:", parameters)

    result = execute(operation["operation"], parameters)
    print("Results:", result)

    # need to add the processor here later

    response = respond(result)
    print("Response:", response)


if __name__ == "__main__":
    main()