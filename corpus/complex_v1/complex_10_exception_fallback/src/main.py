from .support import parse

def fallback(value):
    return 0

def safe_run(value):
    try:
        return parse(value)
    except ValueError:
        return fallback(value)
