from matcher import pattern_matcher
from library.brain import brain

def response(pattern):
    response = ""
    if pattern in brain:
        response = brain[pattern]
    else:
        response = "I'm sorry, I don't understand."
    return response