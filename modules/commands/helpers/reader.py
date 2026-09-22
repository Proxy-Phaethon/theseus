import re
from collections import Counter
from datetime import datetime

import spacy

nlp = spacy.load("en_core_web_sm")

def read(investigation, sources):
    evidence = build_evidence(sources)

    answers = []

    for request in investigation["requests"]:
        request_data = analyze_request(request)

        candidates = find_candidates(
            request_data,
            evidence
        )

        extracted = extract_answers(candidates)

        weighted = weigh_answers(extracted)

        if weighted:
            answers.append({
                "request": request,
                "answer": weighted["answer"],
                "sources": weighted["sources"]
            })

    return answers

def build_evidence(sources):
    evidence = []

    for source in sources:
        content = clean_text(source["content"])
        lines = content.splitlines()

        for index, line in enumerate(lines):
            evidence.append({
                "text": line,
                "source": source["url"],
                "lines": lines,
                "index": index
            })

    return evidence

def analyze_request(request):
    doc = nlp(request)

    tokens = []

    for token in doc:
        if token.is_stop or token.is_punct:
            continue

        tokens.append({
            "text": token.text.lower(),
            "lemma": token.lemma_.lower(),
            "pos": token.pos_
        })

    return {
        "text": request,
        "tokens": tokens
    }

def find_candidates(request, evidence):
    candidates = []

    request_terms = {
        token.lemma_.lower()
        for token in nlp(request["text"])
        if not token.is_stop and not token.is_punct
    }

    for item in evidence:
        document = nlp(item["text"])

        evidence_terms = {
            token.lemma_.lower()
            for token in document
            if not token.is_stop and not token.is_punct
        }

        overlap = request_terms & evidence_terms

        if not overlap:
            continue

        score = len(overlap) / len(request_terms)

        if score < 0.5:
            continue

        candidates.append({
            **item,
            "score": score
        })

    candidates.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return candidates

def extract_answers(candidates):
    answers = []

    for candidate in candidates:
        lines = candidate["lines"]
        index = candidate["index"]
        text = candidate["text"]

        value = extract_inline_value(text)

        if value:
            answers.append({
                "answer": value,
                "source": candidate["source"]
            })
            continue

        if index + 1 < len(lines):
            next_line = lines[index + 1].strip()

            if next_line:
                answers.append({
                    "answer": next_line,
                    "source": candidate["source"]
                })

    return answers

def extract_inline_value(text):
    match = re.search(
        r":\s*(.+)$",
        text
    )

    if match:
        return match.group(1).strip()

    return None

def weigh_answers(answers):
    if not answers:
        return None

    normalized = []

    for answer in answers:
        normalized.append({
            **answer,
            "normalized": normalize_answer(
                answer["answer"]
            )
        })

    counts = Counter(
        answer["normalized"]
        for answer in normalized
        if answer["normalized"]
    )

    if not counts:
        return None

    selected = counts.most_common(1)[0][0]

    supporting = [
        answer
        for answer in normalized
        if answer["normalized"] == selected
    ]

    return {
        "answer": selected,
        "sources": list(dict.fromkeys(
            answer["source"]
            for answer in supporting
        ))
    }

def normalize_answer(answer):
    answer = " ".join(answer.split())

    date_formats = [
        "%d %B %Y",
        "%B %d, %Y",
        "%A, %B %d, %Y",
        "%d %b %Y",
        "%B %d %Y",
    ]

    for date_format in date_formats:
        try:
            date = datetime.strptime(
                answer,
                date_format
            )

            return date.strftime("%d %B %Y")

        except ValueError:
            continue

    return answer.lower()

def clean_text(text):
    lines = []

    for line in text.splitlines():
        line = " ".join(line.split())

        if line:
            lines.append(line)

    return "\n".join(lines)