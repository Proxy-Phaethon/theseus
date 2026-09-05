from command_helper import nlp

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import re

def read(operation, query, pages):
    if operation == "SEARCH":
        return search(query, pages)

    if operation == "FIND":
        return find(query, pages)

    raise ValueError(f"Unknown operation: {operation}")

def search(query, pages):
    terms = nlp.match(query)

    matches = []

    for page in pages:
        text = page.get("text")

        if not text:
            continue

        sentences = split_sentences(text)

        for sentence in sentences:
            sentence = clean_sentence(sentence)

            if not sentence:
                continue

            score = score_sentence(sentence, terms)

            if score > 0:
                matches.append({
                    "text": sentence,
                    "score": score,
                    "source": page.get("url")
                })

    if not matches:
        return None

    matches.sort(
        key=lambda match: match["score"],
        reverse=True
    )

    matches = deduplicate(matches)
    matches = select_evidence(matches)

    return {
        "query": query,
        "matches": matches
    }

def split_sentences(text):
    text = re.sub(
        r"\s+",
        " ",
        text
    ).strip()

    return re.split(
        r"(?<=[.!?])\s+",
        text
    )

def clean_sentence(sentence):
    sentence = re.sub(
        r"\s+",
        " ",
        sentence
    ).strip()

    sentence = re.sub(
        r"\s+([,.;:!?])",
        r"\1",
        sentence
    )

    sentence = re.sub(
        r"([(\[])\s+",
        r"\1",
        sentence
    )

    sentence = re.sub(
        r"\s+([)\]])",
        r"\1",
        sentence
    )

    return sentence

def score_sentence(sentence, terms):
    words = set(
        re.findall(
            r"\b[\w'-]+\b",
            sentence.lower()
        )
    )

    score = 0

    for term in terms:
        term = term.lower()

        if " " not in term:
            if term in words:
                score += 1
        else:
            if term in sentence.lower():
                score += len(term.split())

    return score

def deduplicate(matches):
    if len(matches) <= 1:
        return matches

    sentences = [
        match["text"]
        for match in matches
    ]

    try:
        vectorizer = TfidfVectorizer(
            stop_words="english"
        )

        matrix = vectorizer.fit_transform(sentences)

    except ValueError:
        return matches

    similarities = cosine_similarity(matrix)

    keep = []
    threshold = 0.75

    for i in range(len(matches)):
        duplicate = False

        for j in keep:
            if similarities[i][j] >= threshold:
                duplicate = True
                break

        if not duplicate:
            keep.append(i)

    return [
        matches[i]
        for i in keep
    ]

def select_evidence(matches, limit=8):
    return matches[:limit]

def find(query, pages):
    pass