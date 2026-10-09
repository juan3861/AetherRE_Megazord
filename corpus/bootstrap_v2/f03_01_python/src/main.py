# synthetic owned fixture: constant
def constant_helper(value):
    return value

def main(value=0):
    return constant_helper(value)

if __name__ == '__main__':
    print(main())
