import json
import re
import spacy

from urllib.parse import urlencode
from urllib.request import Request, urlopen

SEARXNG_URL = "http://localhost:8080/search"

nlp = spacy.load("en_core_web_sm")

def understand_query(query):
    doc = nlp(query)

    answer_type = None

    for token in doc:
        word = token.text.lower()

        if word in {"who", "whom"}:
            answer_type = "PERSON"

        elif word == "when":
            answer_type = "DATE"

        elif word == "where":
            answer_type = "PLACE"

        elif word == "how":
            answer_type = "NUMBER"

        elif word == "what":
            answer_type = "UNKNOWN"

    root = next(
        (token for token in doc if token.dep_ == "ROOT"),
        None
    )

    if root is None:
        return {
            "answer_type": answer_type,
            "subject": None,
            "predicate": None,
            "object": None,
            "entities": []
        }

    subject = None
    object_ = None

    for token in root.children:
        if token.dep_ in {"nsubj", "nsubjpass"}:
            if token.text.lower() not in {"who", "whom", "what"}:
                subject = token.text

        elif token.dep_ in {"dobj", "obj"}:
            object_ = token.text

    entities = [
        {
            "text": entity.text,
            "label": entity.label_
        }
        for entity in doc.ents
    ]

    return {
        "answer_type": answer_type,
        "subject": subject,
        "predicate": root.lemma_.lower(),
        "object": object_,
        "entities": entities
    }

def search(query):
    parameters = urlencode({
        "q": query,
        "format": "json"
    })

    url = f"{SEARXNG_URL}?{parameters}"

    request = Request(
        url,
        headers={
            "Accept": "application/json"
        }
    )

    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read())

    return data.get("results", [])

def answer_query(query):
    query_structure = understand_query(query)

    results = search(query)

    candidates = recognize_answer(
        results,
        query_structure
    )

    return rank_answers(candidates)

def recognize_answer(results, query_structure):
    candidates = []

    answer_type = query_structure["answer_type"]
    predicate = query_structure["predicate"]

    if not predicate:
        return candidates

    for result in results:
        content = result.get("content", "")

        if not content:
            continue

        sentences = re.split(
            r"(?<=[.!?])\s+",
            content
        )

        for sentence in sentences:
            sentence = sentence.strip()

            if not sentence:
                continue

            if not matches_predicate(sentence, predicate):
                continue

            answer = extract_answer(
                sentence,
                answer_type,
                predicate
            )

            if answer:
                candidates.append(answer)

    return candidates

def matches_predicate(sentence, predicate):
    doc = nlp(sentence)

    for token in doc:
        if token.lemma_.lower() == predicate:
            return True

    return False

def extract_answer(sentence, answer_type, predicate):
    doc = nlp(sentence)

    predicate_token = None

    for token in doc:
        if token.lemma_.lower() == predicate:
            predicate_token = token
            break

    if predicate_token is None:
        return None

    labels = answer_labels(answer_type)

    for child in predicate_token.children:
        if child.dep_ == "nsubj":
            answer = entity_for_token(doc, child, labels)

            if answer:
                return answer

    for child in predicate_token.children:
        if child.dep_ == "agent":
            for descendant in child.subtree:
                answer = entity_for_token(
                    doc,
                    descendant,
                    labels
                )

                if answer:
                    return answer

    for child in predicate_token.children:
        if child.dep_ != "prep":
            continue

        for descendant in child.subtree:
            answer = entity_for_token(
                doc,
                descendant,
                labels
            )

            if answer:
                return answer

    return None

def entity_for_token(doc, token, labels):
    for entity in doc.ents:
        if entity.label_ not in labels:
            continue

        if entity.start <= token.i < entity.end:
            return entity.text.strip()

    return None

def answer_labels(answer_type):
    if answer_type == "PERSON":
        return {"PERSON"}

    if answer_type == "PLACE":
        return {
            "GPE",
            "LOC",
            "FAC"
        }

    if answer_type == "DATE":
        return {"DATE"}

    if answer_type == "NUMBER":
        return {
            "CARDINAL",
            "QUANTITY",
            "PERCENT"
        }

    return set()

def extract_entity(doc, labels):
    for entity in doc.ents:
        if entity.label_ in labels:
            return entity.text.strip()

    return None

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

def normalize_answer(answer):
    answer = answer.lower().strip()

    answer = answer.replace("&", "and")

    answer = re.sub(
        r"\s+",
        " ",
        answer
    )

    return answer