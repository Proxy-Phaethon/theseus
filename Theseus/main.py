from tokenizer import tokenize
from parser import parse
from responder import response as generate_response

print("Hello, I am Theseus.")

chat = input("How may I help you today? ")

def respond_to_user(chat):
    tokens = tokenize(chat)
    print(tokens)
    meaning = parse(tokens)
    print(meaning)
    response = generate_response(meaning)

    return response

response = respond_to_user(chat)
print(response)