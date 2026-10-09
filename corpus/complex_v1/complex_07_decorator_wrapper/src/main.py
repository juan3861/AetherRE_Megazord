from .support import audit

@audit
def run(value):
    return value + 1

def entry(value):
    return run(value)
