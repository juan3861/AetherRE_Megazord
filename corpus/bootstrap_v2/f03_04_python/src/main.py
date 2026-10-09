# synthetic owned fixture: cycle
def cycle_a(value):
    return cycle_b(value)

def cycle_b(value):
    return cycle_a(value)

def main(value=0):
    return value

if __name__ == '__main__':
    print(main())
