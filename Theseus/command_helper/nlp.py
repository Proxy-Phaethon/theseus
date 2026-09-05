import re

from nltk.corpus import wordnet

def expand(query):
    """
    Expand a query into useful search terms.

    Returns a set containing the original terms,
    morphological variants, and lexical synonyms.
    """

    normalized = normalize(query)
    morphological = morphology(normalized)
    lexical = synonyms(morphological)

    return lexical

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

def morphology(query):
    """
    Generate simple morphological variants.
    """

    words = query.split()
    forms = set(words)

    for word in words:

        if word.endswith("ies") and len(word) > 4:
            forms.add(word[:-3] + "y")

        elif word.endswith("es") and len(word) > 4:
            forms.add(word[:-2])

        elif word.endswith("s") and len(word) > 3:
            forms.add(word[:-1])

        if word.endswith("ing") and len(word) > 5:
            forms.add(word[:-3])

        if word.endswith("ed") and len(word) > 4:
            forms.add(word[:-2])

    return forms

def synonyms(words):
    """
    Expand words using WordNet synonyms.
    """

    expanded = set(words)

    for word in words:

        for synset in wordnet.synsets(word):

            for lemma in synset.lemmas():

                expanded.add(
                    lemma.name().replace("_", " ")
                )

    return expanded