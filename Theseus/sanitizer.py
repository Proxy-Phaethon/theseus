from parser import parse

def sanitize(meaning):
    sanitized_list = []
    for category in meaning:
        if category != "unknown":
            sanitized_list.append(category)
    return sanitized_list