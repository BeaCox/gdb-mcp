#include <stdio.h>

static int add(int a, int b) {
    int total = a + b;
    return total;
}

int main(void) {
    int value = add(2, 40);
    printf("value=%d\n", value);
    return value == 42 ? 0 : 1;
}
