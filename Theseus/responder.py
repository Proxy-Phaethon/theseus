from matcher import pattern_matcher

brain = {
    "intro": "Hey, nice to meet you. I'm Theseus.",
    "casual": "Not much, just hanging out. How about you?",
    "talk": "I'm doing well, thanks for asking. What about you?"
}

def response(pattern):
    response = ""
    if pattern in brain:
        response = brain[pattern]
    else:
        response = "I'm sorry, I don't understand."
    return response