from parser import parse

print(parse(["hi"]))
print(parse(["search", "John", "Smith"]))
print(parse(["search", "John Smith"]))
print(parse([]))