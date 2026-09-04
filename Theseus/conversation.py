# theseus has a personality and stuff
RESPONSES = {
    "hi": "Hey.",
    "hello": "Hello.",
    "hey": "Hey.",
    "how are you": "Operational.",
    "what are you doing": "Waiting for an investigation.",
    "who are you": "Theseus.",
    "thank you": "You're welcome.",
    "thanks": "You're welcome.",
    "what's the weather": "Shouldn't you be working?",
    "tell me a joke": "Shouldn't you be working?",
    "what's 2 + 2": "You have a calculator.",
    "are you sentient": "Irrelevant.",
}

def respond(user_input):
    message = user_input.strip().lower()

    return RESPONSES.get(message)