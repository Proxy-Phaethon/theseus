from collections import Counter
from datetime import datetime

def normalize_answer(answer):
    answer = answer.strip()

    formats = [
        "%d %B %Y",
        "%B %d, %Y",
        "%d %B %Y",
        "%A, %B %d, %Y",
    ]

    for date_format in formats:
        try:
            date = datetime.strptime(answer, date_format)
            return date.strftime("%d %B %Y")
        except ValueError:
            pass

    return " ".join(answer.split())

def weigh_answers(answers):
    normalized = []

    for answer in answers:
        normalized.append({
            **answer,
            "normalized": normalize_answer(answer["answer"])
        })

    counts = Counter(
        answer["normalized"]
        for answer in normalized
    )

    if not counts:
        return None

    winner = counts.most_common(1)[0][0]

    supporting = [
        answer
        for answer in normalized
        if answer["normalized"] == winner
    ]

    return {
        "answer": winner,
        "sources": [
            answer["source"]
            for answer in supporting
        ]
    }

def read(investigation, sources):
    evidence = []

    for source in sources:
        source["content"] = clean_text(source["content"])

        for line in source["content"].splitlines():
            evidence.append({
                "text": line,
                "source": source["url"]
            })

    answers = []

    for request in investigation["requests"]:
        matches = find_answer(request, evidence)

        if matches:
            answer = weigh_answers(matches)

            if answer:
                answer["request"] = request
                answers.append(answer)

    return answers

def find_answer(request, evidence):
    matches = []

    for i, item in enumerate(evidence):
        text = item["text"].strip()

        if request.lower() not in text.lower():
            continue

        if i + 1 >= len(evidence):
            continue

        next_item = evidence[i + 1]

        if next_item["source"] != item["source"]:
            continue

        matches.append({
            "request": request,
            "answer": next_item["text"],
            "source": next_item["source"]
        })

    return matches

def clean_text(text):
    lines = []

    for line in text.splitlines():
        line = " ".join(line.split())

        if line:
            lines.append(line)

    return "\n".join(lines)