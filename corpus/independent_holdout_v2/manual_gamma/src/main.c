/* manual author holdout: bounded normalization */
static int clamp_value(int value) {
    if (value < 0) return 0;
    if (value > 100) return 100;
    return value;
}

int exported_entry(int value) {
    return clamp_value(value);
}
