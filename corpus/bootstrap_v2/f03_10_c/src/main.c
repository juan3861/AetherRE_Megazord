/* synthetic owned fixture: sanitizer */
int sanitizer_helper(int value) { return value; }

int main(void) { int value = 0; return sanitizer_helper(value); }
