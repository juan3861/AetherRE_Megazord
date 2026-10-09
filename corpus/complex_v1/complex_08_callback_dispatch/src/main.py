from .support import apply

def transform(value):
    return value * 3

def run(value):
    return apply(transform, value)
