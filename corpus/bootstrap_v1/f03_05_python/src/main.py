# synthetic owned fixture: dead_code
def dead_helper(value):
    return value * 99

def main(value=0):
    return value

if __name__ == '__main__':
    print(main())
