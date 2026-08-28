#include <stdio.h>

static int helper_mix(int value) {
    return (value * 3) ^ 0x5a;
}

int interesting_function(int a, int b) {
    int total = a + b;
    int mixed = helper_mix(total);

    if ((mixed & 1) == 0) {
        return mixed + 7;
    }
    return mixed - 3;
}

int main(int argc, char **argv) {
    int seed = argc > 1 ? (int)argv[1][0] : 1;
    int result = interesting_function(seed, 42);

    printf("result=%d\n", result);
    return result == 0 ? 1 : 0;
}
