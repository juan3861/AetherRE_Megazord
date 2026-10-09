# synthetic owned fixture: indirect_call
def indirect_helper(value):
    return value + 1

DISPATCH = {'run': indirect_helper}

def main(value=0):
    return value

if __name__ == '__main__':
    print(main())
