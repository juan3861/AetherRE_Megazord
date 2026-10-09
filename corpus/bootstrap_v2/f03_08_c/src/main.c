/* synthetic owned fixture: indirect_call */
int indirect_helper(int value) { return value + 1; }
int (*dispatch)(int) = indirect_helper;

int main(void) { int value = 0; return dispatch(value); }
