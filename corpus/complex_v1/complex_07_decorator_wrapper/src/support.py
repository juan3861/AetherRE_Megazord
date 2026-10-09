def audit(fn):
    def wrapper(value):
        return fn(value)
    return wrapper
