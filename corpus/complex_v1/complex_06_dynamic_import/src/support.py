def fallback(module):
    return getattr(module, 'VALUE', None)
