/* synthetic owned fixture: mock_boundary */
int mock_boundary_helper(int value) { return value; }

int main(void) { int value = 0; return mock_boundary_helper(value); }
