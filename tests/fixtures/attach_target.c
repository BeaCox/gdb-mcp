#include <stdio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif
#endif

volatile int marker = 1234;

int main(void) {
#ifdef __linux__
    (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    puts("ready");
    fflush(stdout);
    while (marker == 1234) {
        sleep(1);
    }
    return 0;
}
