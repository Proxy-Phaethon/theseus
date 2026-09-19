import re

def read(investigation, sources):
    answers = {}

    for request in investigation["requests"]:
        answers[request] = find_answer(
            investigation,
            request,
            sources
        )

    return answers

def find_answer(investigation, request, sources):
    target_name = investigation["target"]["name"]

    target_words = target_name.lower().split()
    request_words = request.lower().split()

    matches = []

    for source in sources:
        content = source["content"]

        sentences = split_sentences(content)

        for sentence in sentences:
            text = sentence.lower()

            target_matches = sum(
                1
                for word in target_words
                if word in text
            )

            request_matches = sum(
                1
                for word in request_words
                if word in text
            )

            score = target_matches + request_matches

            if score > 0:
                matches.append({
                    "score": score,
                    "evidence": sentence.strip(),
                    "source": source["url"],
                    "title": source["title"],
                })

    if not matches:
        return None

    matches.sort(
        key=lambda match: match["score"],
        reverse=True
    )

    return matches[0]

def split_sentences(text):
    return re.split(
        r"(?<=[.!?])\s+",
        text
    )