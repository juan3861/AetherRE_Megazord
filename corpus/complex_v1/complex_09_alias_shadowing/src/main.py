from .left import handle as left_handle
from .right import handle as right_handle

def run(value):
    return left_handle(value) + right_handle(value)
