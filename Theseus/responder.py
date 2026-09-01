from matcher import pattern_matcher

brain = {
    "intro": "Hey, nice to meet you. I'm Theseus."
}

def response(pattern):
    response = ""
    if pattern in brain:
        response = brain[pattern]
    else:
        response = "I'm sorry, I don't understand."
    return response