from sanitizer import sanitize
from tokenizer import tokenize
from parser import parse
from matcher import pattern_matcher
from responder import response as generate_response

print("Hello, I am Theseus.")

chat = input("How may I help you today?\n" )

def respond_to_user(chat):
    tokens = tokenize(chat)
    meaning = parse(tokens)
    sanitized_list = sanitize(meaning)
    pattern = pattern_matcher(sanitized_list)
    response = generate_response(pattern)

    return response

response = respond_to_user(chat)
print(response)

# note for tmrw - add the sanitizer