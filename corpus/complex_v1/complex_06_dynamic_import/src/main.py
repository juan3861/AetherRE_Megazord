import importlib
from .support import fallback

def run(name):
    module = importlib.import_module(name)
    return fallback(module)
