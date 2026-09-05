# Evidence extraction, ranking, cleaning,
# and answer construction.

import re

import spacy

nlp = spacy.load("en_core_web_sm")

def read(operation, query, pages):
    if operation == "SEARCH":
        return search(query, pages)

    if operation == "FIND":
        return find(query, pages)

    raise ValueError(f"Unknown operation: {operation}")

def search(query, pages):
    matches = []

    # Process the query only once.
    query_doc = nlp(query)

    for page in pages:
        text = page.get("text")

        if not text:
            continue

        # Process each page only once.
        doc = nlp(text)

        for sentence in doc.sents:
            cleaned = clean_sentence(sentence.text)

            if not cleaned:
                continue

            score = score_sentence(
                query_doc,
                sentence
            )

            if score > 0:
                matches.append({
                    "sentence": cleaned,
                    "score": score,
                    "url": page.get("url")
                })

    matches.sort(
        key=lambda match: match["score"],
        reverse=True
    )

    matches = deduplicate(matches)

    return build_paragraph(matches)

def clean_sentence(sentence):
    """
    Clean common scraper artifacts.
    """

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

    if not sentence:
        return None

    return sentence

def score_sentence(query_doc, sentence):
    """
    Score how strongly a sentence relates
    to the original query.
    """

    query_lemmas = {
        token.lemma_.lower()
        for token in query_doc
        if not token.is_stop
        and not token.is_punct
        and token.is_alpha
    }

    sentence_lemmas = {
        token.lemma_.lower()
        for token in sentence
        if not token.is_stop
        and not token.is_punct
        and token.is_alpha
    }

    if not query_lemmas:
        return 0

    overlap = (
        query_lemmas
        & sentence_lemmas
    )

    score = 0

    score += len(overlap) * 5

    query_text = query_doc.text.lower().strip()
    sentence_text = sentence.text.lower()

    if query_text in sentence_text:
        score += 10

    for token in query_doc:
        if token.is_stop or token.is_punct:
            continue

        if token.text.lower() in sentence_text:
            score += 2

    return score

def deduplicate(matches):
    """
    Remove duplicate sentences and repeated evidence.
    """

    seen = set()
    unique = []

    for match in matches:
        sentence = match["sentence"]

        key = re.sub(
            r"\W+",
            " ",
            sentence.lower()
        ).strip()

        if key in seen:
            continue

        seen.add(key)
        unique.append(match)

    return unique

def build_paragraph(matches):
    """
    Construct the final reader result.
    """

    if not matches:
        return None

    selected = matches[:8]

    sentences = []
    sources = []
    seen_urls = set()

    for match in selected:
        sentence = clean_sentence(
            match["sentence"]
        )

        if not sentence:
            continue

        sentence = (
            sentence[0].upper()
            + sentence[1:]
        )

        if sentence[-1] not in ".!?":
            sentence += "."

        sentences.append(sentence)

        url = match.get("url")

        if url and url not in seen_urls:
            sources.append(url)
            seen_urls.add(url)

    if not sentences:
        return None

    return {
        "paragraph": " ".join(sentences),
        "sources": sources
    }

def find(query, pages):
    pass