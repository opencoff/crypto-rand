/*
 * Simple test harness and benchmark for AES based random generator
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "cryptorand.h"


extern void error(int doexit, int err, const char* fmt, ...);


int
main(int argc, const char *argv[])
{
    crypto_rand_state st;

    int r = crypto_rand_init(&st, CRYPTO_RAND_AES, getentropy);
    assert(r == 0);

    int n = 1024;

    if (argc > 1) {
        int z = atoi(argv[1]);
        if (z <= 0) error(1, 0, "invalid size %s", argv[1]);
        n = z;
    }

    uint8_t *buf = malloc(n);
    assert(buf);

    crypto_rand_buf(&st, buf, n);

    fwrite(buf, 1, n, stdout);
    free(buf);
    return 0;
}


