/*
 * Simple test harness and benchmark for MT Arc4Random
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "cputime.h"

#include "cryptorand.h"

extern void error(int doexit, int err, const char* fmt, ...);


/*
 * Generate 'siz' byte RNG in a tight loop and provide averages.
 */
static void
bench(int fd, size_t siz, size_t niter)
{
    size_t j;
    uint8_t *buf = malloc(siz);
    uint64_t s0, s1, s2;
    uint64_t ta = 0;    // cumulative time for aesrand
    uint64_t ts = 0;    // cumulative time for system rand
    ssize_t m;

    crypto_rand_state st;

    int r = crypto_rand_init(&st, CRYPTO_RAND_AES, getentropy);
    assert(r == 0);

    for (j = 0; j < niter; ++j) {
        s0 = sys_cpu_timestamp();
        crypto_rand_buf(&st, buf, siz);
        s1 = sys_cpu_timestamp();
        m  =  read(fd, buf, siz);
        s2 = sys_cpu_timestamp();

        if (m < 0) error(1, errno, "Partial read from /dev/urandom; exp %d, saw %d", siz, m);

        ta += s1 - s0;
        ts += s2 - s1;
    }

#define _d(x)   ((double)(x))
    double aa = _d(ta) / _d(niter);     // average of n runs for aesrandom
    double as = _d(ts) / _d(niter);     // average of n runs for sysrand
    double sa = aa / _d(siz);           // cycles/byte for aesrandom
    double ss = as / _d(siz);           // cycles/byte for sysrand

    double speedup = ss / sa;

    printf("%6lu, %9.4f,\t%9.4f,\t%6.2f\n", siz, sa, ss, speedup);

    free(buf);
}



#define NITER       8192

int
main(int argc, const char** argv)
{

    if (argc > 1) {
        int i;

        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) error(1, errno, "Can't open dev/urandom");


        printf("size,      aesrand,\tsysrand,\tspeed-up\n");
        for (i = 1; i < argc; ++i) {
            int z = atoi(argv[i]);
            if (z <= 0) continue;
            bench(fd, z, NITER);
        }


        close(fd);
    }

    return 0;
}


/* EOF */
