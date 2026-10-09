# synthetic owned fixture: callback
def callback_helper(fn, value):
    return fn(value)

def main(value=0):
    return value

if __name__ == '__main__':
    print(main())
