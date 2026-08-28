// Fixture for callees-fallback regression test (PR #20).
//
// `interesting_function` contains both:
//   - a direct call to `direct_callee` (operand kind: Near)
//   - an indirect call through `fptr` in BSS (operand kind: Mem/Displ
//     depending on arch — neither encodes a callee address)
//
// callees(interesting_function) must include direct_callee and must NOT
// include any address sourced from the indirect call's operand. The
// pre-fix fallback in src/ida/handlers/controlflow.rs treated any
// op.address() as a callee, which produced bogus nodes for Mem/Displ.

#include <stdio.h>
#include <stdlib.h>

int direct_callee(int x) { return x * 2; }

int (*fptr)(int);

int interesting_function(int x) {
    int a = direct_callee(x);
    fptr = direct_callee;
    int b = fptr(x);
    return a + b;
}

int main(int argc, char **argv) {
    fptr = direct_callee;
    int n = argc > 1 ? atoi(argv[1]) : 5;
    printf("%d\n", interesting_function(n));
    return 0;
}
