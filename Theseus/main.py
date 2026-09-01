from sanitizer import sanitize
from tokenizer import tokenize
from parser import parse
from matcher import pattern_matcher
from responder import response as generate_response

print("Hello, I am Theseus.")

chat = input("How may I help you today?\n" )

def respond_to_user(chat):
    tokens = tokenize(chat)
    print("Tokens:", tokens)
    meaning = parse(tokens)
    print("Meaning:", meaning)
    sanitized_list = sanitize(meaning)
    print("Sanitized List:", sanitized_list)
    pattern = pattern_matcher(sanitized_list)
    print("Pattern:", pattern)
    response = generate_response(pattern)
    print("Response:", response)

    return response

response = respond_to_user(chat)
print(response)

# note for tmrw - add the sanitizer