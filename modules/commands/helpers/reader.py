def read(investigation, sources):
    answers = []

    for source in sources:
        source["content"] = clean_text(source["content"])

        answer = find_answer(
            investigation,
            source["content"]
        )

        if answer:
            answers.append({
                "answer": answer,
                "source": source["url"]
            })

    return answers

def find_answer(investigation, text):
    requests = investigation["requests"]

    for request in requests:
        lines = text.splitlines()

        for i, line in enumerate(lines):
            if request.lower() in line.lower():
                if i + 1 < len(lines):
                    return lines[i + 1]

    return None

def clean_text(text):
    lines = []

    for line in text.splitlines():
        line = " ".join(line.split())

        if line:
            lines.append(line)

    return "\n".join(lines)