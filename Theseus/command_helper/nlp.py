import re

import spacy
from sentence_transformers import SentenceTransformer

nlp = spacy.load("en_core_web_sm")

model = SentenceTransformer("all-MiniLM-L6-v2")

def expand(query):
    """
    Expand a query into semantically useful search terms.

    The original query is always preserved.
    """

    normalized = normalize(query)

    if not normalized:
        return []

    doc = nlp(normalized)

    candidates = generate_candidates(doc)

    expansions = semantic_rank(
        normalized,
        candidates
    )

    terms = [normalized]

    for term in expansions:
        if term not in terms:
            terms.append(term)

    return terms

def normalize(query):
    """
    Normalize a search query.
    """

    query = query.lower()

    query = re.sub(
        r"[^\w\s]",
        " ",
        query
    )

    query = re.sub(
        r"\s+",
        " ",
        query
    ).strip()

    return query

def generate_candidates(doc):
    """
    Generate possible query expansions.

    This is deliberately conservative for now.
    """

    candidates = set()

    for token in doc:

        if token.is_stop or token.is_punct:
            continue

        word = token.text.lower()
        lemma = token.lemma_.lower()

        if lemma != word:
            candidates.add(lemma)

    return list(candidates)

def semantic_rank(query, candidates):
    """
    Rank candidate terms according to semantic
    similarity with the original query.
    """

    if not candidates:
        return []

    query_embedding = model.encode(
        query,
        normalize_embeddings=True
    )

    candidate_embeddings = model.encode(
        candidates,
        normalize_embeddings=True
    )

    scores = candidate_embeddings @ query_embedding

    ranked = sorted(
        zip(candidates, scores),
        key=lambda item: item[1],
        reverse=True
    )

    expansions = []

    for term, score in ranked:

        if score < 0.5:
            continue

        expansions.append(term)

    return expansions