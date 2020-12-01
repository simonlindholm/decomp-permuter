volatile int A, B, C;

#ifdef ACTUAL
void test_once1(void) {
    A = 1;
    B = 2;
    C = 3;
}
#else
void test_once1(void) {
    PERM_ONCE(B = 2;)
    A = 1;
    PERM_ONCE(B = 2;)
    C = 3;
    PERM_ONCE(B = 2;)
}
#endif

#ifdef ACTUAL
void test_once2(void) {
    A = 1;
    B = 2;
    C = 3;
}
#else
void test_once2(void) {
    PERM_VAR(emit,)
    PERM_VAR(bademit,)
    PERM_ONCE(1, PERM_VAR(bademit, A = 7;) A = 2;)
    PERM_ONCE(1, PERM_VAR(emit, A = 1;))
    PERM_VAR(emit)
    PERM_VAR(bademit)
    PERM_ONCE(2, B = 2;)
    PERM_ONCE(2, B = 1;)
    PERM_ONCE(2,)
    PERM_ONCE(3, PERM_VAR(bademit, A = 9))
    C = 3;
}
#endif
