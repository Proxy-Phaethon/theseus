from identifier import identify


instruction = {
    "command": "SEARCH",
    "arguments": ["John Smith"]
}

print(identify(instruction))