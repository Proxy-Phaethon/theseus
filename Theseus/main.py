from tokenizer import tokenize
from parser import parse
from responder import response as generate_response

print("Hello, I am Theseus.")

chat = input("How may I help you today?\n" )

def respond_to_user(chat):
    tokens = tokenize(chat)
    meaning = parse(tokens)
    response = generate_response(meaning)

    return response

response = respond_to_user(chat)
print(response)