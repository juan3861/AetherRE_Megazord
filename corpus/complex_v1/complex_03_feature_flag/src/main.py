from .support import fast, slow
ENABLED = False

def run(value):
    if ENABLED:
        return fast(value)
    return slow(value)
