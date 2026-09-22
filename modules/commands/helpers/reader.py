import re
from collections import defaultdict

import spacy

nlp = spacy.load("en_core_web_sm")

PROFILE_FIELDS = {
    "person": {
        "target": [
            "name",
            "aliases",
            "usernames",
        ],
        "identity": [
            "date of birth",
            "place of birth",
            "nationality",
            "locations",
            "occupation",
        ],
        "digital_presence": [
            "websites",
            "social accounts",
            "usernames",
            "public profiles",
            "other online identifiers",
        ],
        "professional": [
            "employers",
            "organizations",
            "roles",
            "projects",
            "business affiliations",
        ],
        "education": [
            "institutions",
            "degrees",
            "fields of study",
            "dates",
        ],
        "associations": [
            "people",
            "organizations",
            "companies",
            "locations",
            "events",
        ],
        "activity": [
            "recent public activity",
            "notable appearances",
            "publications",
            "public statements",
            "other activity",
        ],
    },

    "company": {
        "target": [
            "legal name",
            "common names",
            "former names",
        ],
        "identity": [
            "founded",
            "founders",
            "headquarters",
            "locations",
            "industry",
            "description",
            "status",
        ],
        "leadership": [
            "executives",
            "directors",
            "officers",
            "board members",
            "key personnel",
        ],
        "ownership": [
            "parent company",
            "subsidiaries",
            "owners",
            "shareholders",
            "investors",
            "beneficial owners",
        ],
        "operations": [
            "products",
            "services",
            "brands",
            "markets",
            "locations",
            "projects",
        ],
        "digital_presence": [
            "websites",
            "social accounts",
            "domains",
            "public profiles",
            "other online identifiers",
        ],
        "financial": [
            "financial information",
            "revenue",
            "valuation",
            "funding",
            "investors",
            "filings",
        ],
        "associations": [
            "people",
            "companies",
            "organizations",
            "governments",
            "partners",
            "competitors",
        ],
        "legal_regulatory": [
            "registrations",
            "licenses",
            "legal proceedings",
            "regulatory actions",
            "filings",
        ],
        "activity": [
            "recent activity",
            "announcements",
            "acquisitions",
            "partnerships",
            "product launches",
            "other activity",
        ],
    },

    "event": {
        "target": [
            "official name",
            "alternative names",
            "event type",
        ],
        "details": [
            "date",
            "time",
            "duration",
            "status",
            "description",
        ],
        "location": [
            "venue",
            "city",
            "region",
            "country",
            "coordinates",
        ],
        "organization": [
            "organizer",
            "host",
            "sponsors",
            "partners",
            "affiliates",
        ],
        "participants": [
            "people",
            "organizations",
            "companies",
            "speakers",
            "performers",
            "other participants",
        ],
        "activity": [
            "schedule",
            "announcements",
            "incidents",
            "notable occurrences",
            "related events",
        ],
        "digital_presence": [
            "official website",
            "social accounts",
            "hashtags",
            "livestreams",
            "videos",
            "online references",
        ],
        "impact_context": [
            "purpose",
            "significance",
            "related organizations",
            "related people",
            "consequences",
            "aftermath",
        ],
    },
}

def clean_sentence(sentence):
    return " ".join(sentence.split())

def split_sentences(text):
    document = nlp(text)

    return [
        clean_sentence(sentence.text)
        for sentence in document.sents
        if clean_sentence(sentence.text)
    ]

def field_terms(field):
    return set(
        re.findall(
            r"[a-zA-Z]+",
            field.lower()
        )
    )

def sentence_score(sentence, field):
    sentence_words = set(
        re.findall(
            r"[a-zA-Z]+",
            sentence.lower()
        )
    )

    terms = field_terms(field)

    return len(sentence_words & terms)

def relevant_sentences(field, sources):
    candidates = []

    for source in sources:
        content = source.get("content", "")

        if not content:
            continue

        for sentence in split_sentences(content):
            score = sentence_score(
                sentence,
                field
            )

            if score:
                candidates.append({
                    "sentence": sentence,
                    "score": score,
                    "source": source,
                })

    candidates.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return candidates

def extract_entities(sentence):
    document = nlp(sentence)

    entities = []

    for entity in document.ents:
        entities.append({
            "text": entity.text,
            "type": entity.label_,
        })

    return entities

def build_finding(candidate, field):
    sentence = candidate["sentence"]
    source = candidate["source"]

    return {
        "field": field,
        "value": extract_entities(sentence),
        "evidence": sentence,
        "source": source.get("url"),
        "score": candidate["score"],
    }

def read(investigation, sources):
    target_type = investigation["target"]["type"]

    fields = PROFILE_FIELDS.get(
        target_type,
        {}
    )

    profile = defaultdict(dict)

    for section, section_fields in fields.items():
        for field in section_fields:
            candidates = relevant_sentences(
                field,
                sources
            )

            if not candidates:
                continue

            findings = [
                build_finding(
                    candidate,
                    field
                )
                for candidate in candidates[:5]
            ]

            profile[section][field] = findings

    return dict(profile)