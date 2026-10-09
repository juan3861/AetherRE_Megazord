/* synthetic owned fixture: callback */
int callback_helper(int (*fn)(int), int value) { return fn(value); }

int main(void) { int value = 0; return callback_helper(0, value); }
