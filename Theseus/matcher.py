from parser import parse

pattern = {
    ("greeting", "identity", "name"): "intro",
    ("question", "question"): "casual",
    ("question", "greeting"): "talk",
}

def pattern_matcher(meaning):
    for key in pattern:
        if all(category in key for category in meaning):
            return pattern[key]
    return "unknown"