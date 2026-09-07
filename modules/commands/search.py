import json
import re
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SEARXNG_URL = "http://localhost:8080/search"

def classify_query(query):
    query = query.lower().strip()

    if re.match(r"^(who|whom)\b", query):
        return "PERSON"

    if re.match(r"^(where)\b", query):
        return "PLACE"

    if re.match(r"^(when)\b", query):
        return "DATE"

    if re.match(r"^(how many|how much)\b", query):
        return "NUMBER"

    if re.match(r"^(what is|what are|define|definition of)\b", query):
        return "DEFINITION"

    return "FACT"

def search(query):
    url = f"{SEARXNG_URL}?{urlencode({'q': query, 'format': 'json'})}"
    request = Request(url, headers={"Accept": "application/json"})

    with urlopen(request, timeout=10) as response:
        return json.loads(response.read())["results"]

def recognize_answer(query, results, answer_type):
    candidates = []

    for result in results:
        content = result.get("content", "")

        if not content:
            continue

        sentences = re.split(r"(?<=[.!?])\s+", content)

        for sentence in sentences:
            if matches_answer_type(sentence, answer_type):
                candidates.append(sentence)

    return candidates

def matches_answer_type(sentence, answer_type):
    if answer_type == "PERSON":
        return bool(
            re.search(
                r"\b(founded|created|invented|discovered|born|died|married)\b",
                sentence,
                re.IGNORECASE
            )
        )

    if answer_type == "DATE":
        return bool(
            re.search(
                r"\b(19|20)\d{2}\b",
                sentence
            )
        )

    if answer_type == "NUMBER":
        return bool(
            re.search(
                r"\b\d+(?:,\d{3})*(?:\.\d+)?\b",
                sentence
            )
        )

    return False