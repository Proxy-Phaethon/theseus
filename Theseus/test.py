from tokenizer import tokenize

print(tokenize("hi"))
print(tokenize("search John Smith"))
print(tokenize('search "John Smith"'))
print(tokenize('search "John Smith" "Acme Corporation"'))