from parser import parse

pattern = {
    ("greeting", "identity", "name"): "intro"
}

def pattern_matcher(meaning):
    meaning = tuple(meaning)
    if meaning in pattern:
        return pattern[meaning]
    else:
        return "unknown"