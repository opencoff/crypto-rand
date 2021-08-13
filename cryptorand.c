/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 * Copyright (c) 2015, Sudhi Herle   <sudhi@herle.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/*
 * Chacha/AES based random number generator based on OpenBSD
 * arc4random. Generalized to use chacha20 OR AES-256-CTR
 *
 * This cryptographic random generator passes NIST-SP-800-22 (Rev 1).
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>

#include "cryptorand.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))


// Every these many bytes, we reseed and reset the rand state
#define RAND_RESEED_BYTES   (128 * 1024)

// rekey the aes state
static inline void
_rs_rekey(crypto_rand_state* st, uint8_t *dat, size_t datlen)
{
    st->crypt_buf(st);

    /* mix in optional user provided data */
    if (dat) {
        size_t i, m;

        m = minimum(datlen, sizeof st->buf);
        for (i = 0; i < m; i++)
            st->buf[i] ^= dat[i];

        memset(dat, 0, datlen);
    }

    /* immediately reinit for backtracking resistance */
    st->crypt_reinit(st);
}


// stir the pot by rekeying
static void
_rs_stir(crypto_rand_state* st)
{
    st->crypt_rekey(st);

    /* invalidate rand buf */
    memset(st->buf, 0, sizeof st->buf);
    st->ptr   = st->buf + sizeof st->buf;
    st->count = RAND_RESEED_BYTES;
}


// maybe stir the pot
static inline void
_rs_stir_if_needed(crypto_rand_state* st, size_t len)
{
    if (st->count <= len)
        _rs_stir(st);

    // We explicitly don't worry about underflow because we want
    // this to be somewhat random after we stir.
    st->count -= len;
}


// virtual funcs for selecting AES-256-CTR vs CHACHA20
#include "cipher.h"


static void
_chacha_setup(crypto_rand_state *st)
{
    st->crypt_buf    = __chacha_crypt_buf;
    st->crypt_reinit = __chacha_reinit;
    st->crypt_rekey  = __chacha_rekey;
}

static void
_aes_setup(crypto_rand_state *st)
{
    st->crypt_buf    = __aes_crypt_buf;
    st->crypt_reinit = __aes_reinit;
    st->crypt_rekey  = __aes_rekey;
}


/*
 * External API
 */


// initialize the aesrand generator
int
crypto_rand_init(crypto_rand_state *st, int algo, crypto_rand_entropy_t entropy)
{
    if (!entropy) return -EINVAL;


    memset(st, 0, sizeof *st);
    st->entropy = entropy;

    switch (algo) {
        case CRYPTO_RAND_AES:
            _aes_setup(st);
            __aes_init(st);
            break;

        case CRYPTO_RAND_CHACHA20:
            _chacha_setup(st);
            __chacha_init(st);
            break;

        default:
            return -EINVAL;
    }

    // When we startup, st->buf is zero so, we're encrypting a
    // zero-buf with a random key & IV.
    _rs_rekey(st, 0, 0);
    return 0;
}


// fill buffer with randomness
void
crypto_rand_buf(crypto_rand_state* st, void *buf, size_t n)
{
    uint8_t *end = st->buf + sizeof st->buf;

    _rs_stir_if_needed(st, n);
    while (n > 0) {
        size_t avail = end - st->ptr;
        if (avail > 0) {
            size_t m = minimum(n, avail);

            memcpy(buf, st->ptr, m);

            buf     += m;
            n       -= m;
            st->ptr += m;
        } else 
            _rs_rekey(st, NULL, 0);
    }
}


/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint32_t
crypto_rand_uniform32_bounded(crypto_rand_state *st, uint32_t upper_bound)
{
    uint32_t r, min;

    if (upper_bound < 2)
        return 0;

    /* 2**32 % x == (2**32 - x) % x */
    min = -upper_bound % upper_bound;

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    for (;;) {
        r = crypto_rand_uniform32(st);
        if (r >= min)
            break;
    }

    return r % upper_bound;
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**64 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**64 % upper_bound, 2**64) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint64_t
crypto_rand_uniform64_bounded(crypto_rand_state *st, uint64_t upper_bound)
{
    uint64_t r, min;

    if (upper_bound < 2)
        return 0;

    /* 2**64 % x == (2**64 - x) % x */
    min = -upper_bound % upper_bound;

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    for (;;) {
        r = crypto_rand_uniform64(st);
        if (r >= min)
            break;
    }

    return r % upper_bound;
}
/* EOF */
