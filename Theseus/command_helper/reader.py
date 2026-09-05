import re

def read(pages, query):
    if not pages:
        return None

    documents = []

    for page in pages:
        text = page.get("text")

        if not text:
            continue

        sentences = split_sentences(text)

        if not sentences:
            continue

        documents.append({
            "title": page.get("title"),
            "url": page.get("url"),
            "sentences": sentences
        })

    if not documents:
        return None

    relevant_sentences = find_relevant_sentences(
        documents,
        query
    )

    if not relevant_sentences:
        return None

    paragraph = build_paragraph(relevant_sentences)

    sources = []

    for document in documents:
        sources.append({
            "title": document["title"],
            "url": document["url"]
        })

    return {
        "title": query,
        "paragraph": paragraph,
        "sources": sources
    }

def split_sentences(text):
    text = re.sub(r"\s+", " ", text).strip()

    if not text:
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text)

    return [
        sentence.strip()
        for sentence in sentences
        if sentence.strip()
    ]

def find_relevant_sentences(documents, query):
    query_words = set(
        word.lower()
        for word in re.findall(r"\b\w+\b", query)
    )

    matches = []

    for document in documents:
        for sentence in document["sentences"]:
            sentence_words = set(
                word.lower()
                for word in re.findall(r"\b\w+\b", sentence)
            )

            overlap = query_words & sentence_words

            if overlap:
                matches.append({
                    "sentence": sentence,
                    "score": len(overlap),
                    "url": document["url"]
                })

    matches.sort(
        key=lambda match: match["score"],
        reverse=True
    )

    return matches

def build_paragraph(matches):
    sentences = []

    for match in matches[:3]:
        sentences.append(match["sentence"])

    return " ".join(sentences)