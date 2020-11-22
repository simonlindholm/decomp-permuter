#ifdef ACTUAL
int test_ignore(int a, int b) {
    return a / b;
}
#else
int test_ignore(int a, int b) {
    PERM_IGNORE(
    return a / PERM_GENERAL(a, b);
    )
}
#endif
