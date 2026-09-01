from sanitizer import sanitize
from library.patterns import patterns

def pattern_matcher(sanitized_list):
    for key in patterns:
        if all(category in key for category in sanitized_list):
            return patterns[key]
    return "unknown"