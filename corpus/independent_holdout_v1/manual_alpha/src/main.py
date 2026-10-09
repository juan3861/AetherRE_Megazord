def normalize(value):
    return str(value).strip().lower()

def score(value):
    return len(normalize(value))

def entrypoint(value):
    return score(value)
