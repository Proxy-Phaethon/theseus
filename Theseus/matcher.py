from sanitizer import sanitize
from library.patterns import patterns

def pattern_matcher(sanitized_list):
    if not sanitized_list:
        return "unknown"
    for key in patterns:
        if all(category in sanitized_list for category in key):
            return patterns[key]
    return "unknown"