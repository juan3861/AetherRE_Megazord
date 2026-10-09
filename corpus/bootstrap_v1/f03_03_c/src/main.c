/* synthetic owned fixture: callback */
int callback_helper(int (*fn)(int), int value) { return fn(value); }

int main(void) { return 0; }
