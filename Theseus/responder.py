from parser import parse

brain = {
    "greeting": "Hey.",
    "identity": "Nice to meet you!",
    "name": "That's a great name! I'm Theseus, your virtual assistant.",
}

def response(meaning):
    response = ""
    for category in meaning:
        if category in brain:
            response += brain[category] + "\n"
        else:
            response += "I'm sorry, I don't understand.\n"
    return response