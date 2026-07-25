#include <stdio.h>

extern int shared_add(int left, int right);

int main(void) {
    int value = shared_add(19, 23);
    printf("value=%d\n", value);
    return value == 42 ? 0 : 1;
}
