# Operations → parameters
def extract(operation):
    if operation["operation"] == "SEARCH":
        parameters = operation["parameters"]

        if not parameters:
            raise ValueError("Search requires a query")

        if parameters[0].lower() == "for":
            parameters = parameters[1:]

        if not parameters:
            raise ValueError("Search requires a query")

        return {
            "query": " ".join(parameters)
        }

    raise ValueError(
        f"Cannot extract parameters for: {operation['operation']}"
    )