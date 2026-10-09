# synthetic owned fixture: sanitizer
def sanitizer_helper(value):
    return value

def main(value=0):
    return sanitizer_helper(value)

if __name__ == '__main__':
    print(main())
