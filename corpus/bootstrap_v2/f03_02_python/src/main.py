# synthetic owned fixture: branch
def branch_helper(value):
    return value

def main(value=0):
    return branch_helper(value)

if __name__ == '__main__':
    print(main())
