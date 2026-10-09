static int add_one(int value) { return value+1; }
static int add_two(int value) { return add_one(add_one(value)); }
int exported_iota(int value) { return add_two(value); }
