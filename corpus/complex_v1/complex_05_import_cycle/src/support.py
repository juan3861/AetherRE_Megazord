from .main import run

def ping(value):
    return run(value - 1) if value > 0 else 0
