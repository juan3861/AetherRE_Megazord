static int choose(int value) { return value ? value*2 : -1; }
int exported_lambda(int value) { return choose(value); }
