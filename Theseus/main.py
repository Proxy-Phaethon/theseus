from tokenizer import tokenize
from parser import parse
from matcher import pattern_matcher
from responder import response as generate_response

print("Hello, I am Theseus.")

chat = input("How may I help you today?\n" )

def respond_to_user(chat):
    tokens = tokenize(chat)
    meaning = parse(tokens)
    pattern = pattern_matcher(meaning)
    response = generate_response(pattern)

    return response

response = respond_to_user(chat)
print(response)

# note for tmrw - add the sanitizer