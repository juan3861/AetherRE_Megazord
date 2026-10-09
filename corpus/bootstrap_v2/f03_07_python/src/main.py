# synthetic owned fixture: mock_boundary
def mock_boundary_helper(value):
    return value

def main(value=0):
    return mock_boundary_helper(value)

if __name__ == '__main__':
    print(main())
