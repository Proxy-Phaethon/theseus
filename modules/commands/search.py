import json
import re
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SEARXNG_URL = "http://localhost:8080/search"

def classify_query(query):
    query = query.lower().strip()

    if re.search(r"\b(ceo|chief executive)\b", query):
        return "PERSON", "CEO"

    if re.search(r"\b(founder|founded)\b", query):
        if re.match(r"^(who|whom)\b", query) or "founder" in query:
            return "PERSON", "FOUNDED"

    if re.search(r"\b(inventor|invented)\b", query):
        return "PERSON", "INVENTED"

    if re.match(r"^(who|whom)\b", query):
        return "PERSON", "UNKNOWN"

    if re.search(r"\bpopulation\b", query):
        return "NUMBER", "POPULATION"

    if re.match(r"^where\b", query):
        if re.search(
            r"\borigin\b|\boriginate\b|\boriginated\b|\borigins\b",
            query
        ):
            return "PLACE", "ORIGIN"

        return "PLACE", "UNKNOWN"

    if re.match(r"^when\b", query):
        if re.search(r"\bfounded\b|\bestablished\b", query):
            return "DATE", "FOUNDED"

        return "DATE", "UNKNOWN"

    if re.match(r"^(how many|how much)\b", query):
        if re.search(
            r"\bpeople\b|\bpopulation\b|\binhabitants\b",
            query
        ):
            return "NUMBER", "POPULATION"

        return "NUMBER", "UNKNOWN"

    if re.match(r"^(what is|what are|define|definition of)\b", query):
        return "DEFINITION", "UNKNOWN"

    return "FACT", "UNKNOWN"

def search(query):
    url = f"{SEARXNG_URL}?{urlencode({
        'q': query,
        'format': 'json'
    })}"

    request = Request(
        url,
        headers={"Accept": "application/json"}
    )

    with urlopen(request, timeout=10) as response:
        return json.loads(response.read())["results"]

def recognize_answer(query, results, answer_type, relation):
    candidates = []

    for result in results:
        content = result.get("content", "")

        if not content:
            continue

        sentences = re.split(r"(?<=[.!?])\s+", content)

        for sentence in sentences:
            sentence = sentence.strip()

            if not sentence:
                continue

            if matches_answer_type(sentence, answer_type, relation):
                answer = extract_answer(sentence, answer_type, relation)

                if answer:
                    if answer_type == "PERSON" and not valid_person(answer):
                        continue

                    candidates.append(answer)

    return candidates

def matches_answer_type(sentence, answer_type, relation):
    if answer_type == "PERSON":
        return matches_person(sentence, relation)

    if answer_type == "PLACE":
        return matches_place(sentence, relation)

    if answer_type == "DATE":
        return matches_date(sentence, relation)

    if answer_type == "NUMBER":
        return matches_number(sentence)

    if answer_type == "DEFINITION":
        return bool(
            re.search(
                r"\b(is|are|refers to|means|defined as)\b",
                sentence,
                re.IGNORECASE
            )
        )

    return False

def matches_person(sentence, relation):
    patterns = {
        "FOUNDED": (
            r"\bfounded\b|\bfounder\b|\bco-founded\b"
        ),
        "CEO": (
            r"\bceo\b|\bchief executive\b"
        ),
        "INVENTED": (
            r"\binvented\b|\binventor\b"
        ),
        "UNKNOWN": (
            r"\bfounded\b|\bcreated\b|\binvented\b|"
            r"\bdiscovered\b|\bborn\b|\bdied\b|\bmarried\b"
        ),
    }

    pattern = patterns.get(relation, patterns["UNKNOWN"])

    return bool(re.search(pattern, sentence, re.IGNORECASE))

def matches_place(sentence, relation):
    if relation == "ORIGIN":
        return bool(
            re.search(
                r"\borigin\b|\boriginated\b|\bnative to\b|\bnative\b",
                sentence,
                re.IGNORECASE
            )
        )

    return bool(
        re.search(
            r"\bin\b|\bat\b|\bfrom\b|\blocated\b|\bbased\b",
            sentence,
            re.IGNORECASE
        )
    )

def matches_date(sentence, relation):
    if relation == "FOUNDED":
        return bool(
            re.search(
                r"\bfounded\b|\bestablished\b",
                sentence,
                re.IGNORECASE
            )
            and re.search(
                r"\b(19|20)\d{2}\b",
                sentence
            )
        )

    return bool(
        re.search(
            r"\b(19|20)\d{2}\b",
            sentence
        )
    )

def matches_number(sentence):
    return bool(
        re.search(
            r"\b\d+(?:,\d{3})*(?:\.\d+)?\b",
            sentence
        )
    )

def extract_answer(sentence, answer_type, relation):
    if answer_type == "PERSON":
        return extract_person(sentence, relation)

    if answer_type == "DATE":
        return extract_date(sentence, relation)

    if answer_type == "NUMBER":
        return extract_number(sentence, relation)

    if answer_type == "PLACE":
        return extract_place(sentence, relation)

    return None

def extract_person(sentence, relation):
    if relation == "CEO":
        patterns = [
            r"^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s+is\s+"
            r"(?:the\s+)?(?:chairman\s+and\s+)?"
            r"(?:chief executive officer|CEO)",

            r"(?:CEO|chief executive officer)\s+"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, sentence)

            if match:
                return match.group(1).strip()

    if relation == "FOUNDED":
        patterns = [
            # "Microsoft was founded by Bill Gates and Paul Allen"
            r"\bfounded\s+by\s+"
            r"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*"
            r"(?:\s+and\s+[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)?)",

            # "Founded in 1975 by Bill Gates and Paul Allen"
            r"\bfounded\s+in\s+"
            r"(?:\d{4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})"
            r"\s+by\s+"
            r"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*"
            r"(?:\s+and\s+[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)?)",

            # "Bill Gates and Paul Allen founded Microsoft"
            r"^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*"
            r"\s+and\s+[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)"
            r"\s+(?:co-)?founded\b",

            # "Bill Gates co-founded Microsoft"
            r"^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)"
            r"\s+co-founded\b",
        ]

        for pattern in patterns:
            match = re.search(pattern, sentence)

            if match:
                return match.group(1).strip()

    if relation == "INVENTED":
        patterns = [
            # "Alexander Graham Bell invented the telephone"
            r"^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)+)\s+"
            r"invented\b",

            # "The telephone was invented by Alexander Graham Bell"
            r"\binvented\s+by\s+"
            r"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)+)",

            # "Alexander Graham Bell is credited with inventing the telephone"
            r"^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)+)\s+"
            r"is\s+credited\s+with\s+inventing\b",

            # "The inventor of the telephone was Alexander Graham Bell"
            r"\binventor\s+of\b.*?\bwas\s+"
            r"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, sentence)

            if match:
                return match.group(1).strip()

    return None

def extract_date(sentence, relation):
    if relation == "FOUNDED":
        patterns = [
            # "founded on April 4, 1975"
            r"\bfounded\s+on\s+"
            r"((?:January|February|March|April|May|June|July|August|"
            r"September|October|November|December)\s+"
            r"\d{1,2},?\s+(?:19|20)\d{2})",

            # "founded in 1975"
            r"\bfounded\s+in\s+((?:19|20)\d{2})",

            # "On April 4, 1975, ... founded"
            r"\bOn\s+"
            r"((?:January|February|March|April|May|June|July|August|"
            r"September|October|November|December)\s+"
            r"\d{1,2},?\s+(?:19|20)\d{2})"
            r".{0,100}\bfounded\b",
        ]

        for pattern in patterns:
            match = re.search(
                pattern,
                sentence,
                re.IGNORECASE
            )

            if match:
                return match.group(1)

        return None

    match = re.search(
        r"\b(19|20)\d{2}\b",
        sentence
    )

    if match:
        return match.group(0)

    return None

def extract_number(sentence, relation):
    if relation == "POPULATION":
        patterns = [
            # "The current population of Japan is 122,330,957"
            r"\bpopulation\b.*?\bis\s+"
            r"(\d+(?:,\d{3})*(?:\.\d+)?(?:\s*[KMB])?)",

            # "Japan's population stood at 123,767,642"
            r"\bpopulation\b.*?\bstood at\s+"
            r"(\d+(?:,\d{3})*(?:\.\d+)?(?:\s*[KMB])?)",

            # "Japan has a total population of 122,427,731"
            r"\bpopulation\s+of\s+"
            r"(\d+(?:,\d{3})*(?:\.\d+)?(?:\s*[KMB])?)",
        ]

        for pattern in patterns:
            match = re.search(
                pattern,
                sentence,
                re.IGNORECASE
            )

            if match:
                return match.group(1)

        return None

    match = re.search(
        r"\b\d+(?:,\d{3})*(?:\.\d+)?\b",
        sentence
    )

    if match:
        return match.group(0)

    return None

def extract_place(sentence, relation):
    if relation == "ORIGIN":
        patterns = [
            r"\boriginated\s+in\s+([A-Z][A-Za-z]*)",
            r"\bnative\s+to\s+([A-Z][A-Za-z]*)",
            r"\borigins\s+in\s+([A-Z][A-Za-z]*)",
            r"\bcame\s+from\s+([A-Z][A-Za-z]*)",
            r"\btraces\s+back\s+to\s+([A-Z][A-Za-z]*)",
            r"\borigin\s+of\b.*?\bis\s+([A-Z][A-Za-z]*)",
            r"\borigin\s+of\b.*?\bwas\s+([A-Z][A-Za-z]*)",
        ]

        for pattern in patterns:
            match = re.search(pattern, sentence)

            if match:
                return match.group(1).strip()

    return None

def valid_person(candidate):
    candidate = candidate.strip()

    words = candidate.split()

    if len(words) < 2:
        return False

    return all(
        word[0].isupper()
        for word in words
        if word.lower() not in {"and"}
    )

def normalize_answer(answer):
    answer = answer.lower().strip()

    answer = answer.replace("&", "and")

    answer = re.sub(r"\s+", " ", answer)

    return answer

def rank_answers(candidates):
    if not candidates:
        return None

    counts = {}

    for candidate in candidates:
        normalized = normalize_answer(candidate)

        if normalized not in counts:
            counts[normalized] = {
                "answer": candidate,
                "count": 0
            }

        counts[normalized]["count"] += 1

    ranked = sorted(
        counts.values(),
        key=lambda item: item["count"],
        reverse=True
    )

    return ranked[0]["answer"]