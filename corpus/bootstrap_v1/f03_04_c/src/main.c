/* synthetic owned fixture: cycle */
int cycle_b(int value);
int cycle_a(int value) { return cycle_b(value); }
int cycle_b(int value) { return cycle_a(value); }

int main(void) { return 0; }
