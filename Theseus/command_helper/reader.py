from command_helper import nlp

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

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
            score = score_sentence(sentence, terms)

            if score > 0:
                matches.append({
                    "sentence": sentence,
                    "score": score,
                    "url": page.get("url")
                })

    matches.sort(
        key=lambda match: match["score"],
        reverse=True
    )

    cleaned_matches = clean_matches(matches)

    return build_paragraph(cleaned_matches)

def split_sentences(text):
    return text.split(".")

def score_sentence(sentence, terms):
    words = set(
        sentence.lower().split()
    )

    return sum(
        term in words
        for term in terms
    )

def clean_matches(matches):
    if not matches:
        return []

    sentences = [
        match["sentence"].strip()
        for match in matches
        if match["sentence"].strip()
    ]

    if not sentences:
        return []

    vectorizer = TfidfVectorizer()

    matrix = vectorizer.fit_transform(sentences)

    similarities = cosine_similarity(matrix)

    keep = []
    
    threshold = 0.75

    for i, sentence in enumerate(sentences):
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

def find(query, pages):
    pass

def build_paragraph(matches):
    if not matches:
        return None

    sentences = []
    sources = []
    seen_urls = set()

    for match in matches:
        sentence = match["sentence"].strip()

        if not sentence:
            continue

        sentence = sentence[0].upper() + sentence[1:]

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