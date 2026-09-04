from executor import execute


operation = "SEARCH"
parameters = {
    "query": "John Smith"
}

print(execute(operation, parameters))