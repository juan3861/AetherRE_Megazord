def tokenize(value):
    return str(value).split()

def first_token(value):
    parts = tokenize(value)
    return parts[0] if parts else ""

def entrypoint(value):
    return first_token(value)
