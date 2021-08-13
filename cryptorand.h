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

#ifndef ___CRYPTORAND_H_401837192_1462841354__
#define ___CRYPTORAND_H_401837192_1462841354__ 1

    /* Provide C linkage for symbols declared here .. */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/*
 * Chacha20/AES based random number generated derived from OpenBSD
 * arc4random(2).
 *
 * This cryptographic random generator passes NIST-SP-800-22 (Rev 1).
 *
 * (c) 2015-2021 Sudhi Herle <sudhi@herle.net>
 */

#include <stdint.h>
#include <sys/types.h>

#include "chacha_private.h"
#include "aes.h"

// chacha20 parameters
#define ARC4R_KEYSZ     32
#define ARC4R_IVSZ      8
#define ARC4R_BLOCKSZ   64

// AES parameters
#define AESRAND_KEYSZ     AES_KEYLEN
#define AESRAND_IVSZ      AES_BLOCKLEN
#define AESRAND_BLOCKSZ   AES_BLOCKLEN

// Adjust this to change amount of keystream buffer to hold in the
// rand state (in units of cipher basic blocks). Must be greater
// than 4.
//
// NB: Smaller number of blocks => more frequent re-keying from the
// entropy source.
#define __RSBLOCKS   16

#define __max(a,b) ((a) > (b) ? (a) : (b))
#define __RSBUFSZ   (__RSBLOCKS * __max(ARC4R_BLOCKSZ, AESRAND_BLOCKSZ))


// fetch n bytes of entropy from the system and fill the output
// buffer
typedef int (*crypto_rand_entropy_t)(void *, size_t);


// random generator state
struct crypto_rand_state
{
    uint8_t    buf[__RSBUFSZ];  /* rand bytes */
    uint8_t*   ptr;     /* current pointer */
    size_t     count;   /* bytes till reseed */
    union {
        chacha_ctx chacha;  /* chacha20 context */
        AES_ctx    aes;
    };
    crypto_rand_entropy_t entropy;

    /* internal virtual funcs */

    // encrypt buf with the current key in CTR mode
    void (*crypt_buf)(struct crypto_rand_state *);

    // Re-initialize the cipher state with random keys
    void (*crypt_reinit)(struct crypto_rand_state *);

    // Regenerate new keys and update crypto-rand state
    void (*crypt_rekey)(struct crypto_rand_state *);
};
typedef struct crypto_rand_state crypto_rand_state;



#define CRYPTO_RAND_AES      1
#define CRYPTO_RAND_CHACHA20 2

/*
 * Initialize the random generator state using the given cipher
 * algo (must be one of CRYPTO_RAND_AES or CRYPTO_RAND_CHACHA20).
 *
 * Use the supplied function to fetch entropy when we need it.
 */
extern int crypto_rand_init(crypto_rand_state *, int algo, crypto_rand_entropy_t entropy);


/*
 * Fill a buffer with random data
 */
extern void crypto_rand_buf(crypto_rand_state *, void *buf, size_t nbytes);


/*
 * Return a uniform random uint64
 */
extern uint64_t crypto_rand_uniform64_bounded(crypto_rand_state *, uint64_t upper_bound);


/*
 * Return a uniform random uint32
 */
extern uint32_t crypto_rand_uniform32_bounded(crypto_rand_state *, uint32_t upper_bound);


/*
 * Return a uniform uint64
 */
static inline uint64_t
crypto_rand_uniform64(crypto_rand_state *st)
{
    uint64_t z = 0;
    crypto_rand_buf(st, &z, sizeof z);
    return z;
}

/*
 * Return a uniform uint32
 */
static inline uint32_t
crypto_rand_uniform32(crypto_rand_state *st)
{
    uint32_t z = 0;
    crypto_rand_buf(st, &z, sizeof z);
    return z;
}


// uncomment if rand_double is needed
#if 0

/*
 * Return a random float64 in the range [0.0, 1.0).
 *
 * Notes
 * =====
 * IEEE 754 double precision format:
 *   bit 63: sign
 *   bit 62-52: exponent (11 bits)
 *   Bit 51-0:  fraction.
 *
 * So, when we set sign = 0 and exponent = 0xfff, then the format
 * represents a normalized number in the range [1, 2).
 *
 * So, if we can manage to fill the 52 bits with random bits, we
 * will have a normalized random number in the range [1, 2). Then,
 * we subtract 1.0 and voila - we have a random number in the range
 * [0, 1.0).
 */
static inline double
crypto_rand_double(crypto_rand_state *st)
{
    union {
        double   d;
        uint64_t v;
    } un;

    uint64_t r = crypto_rand_uniform64(st) & ~0xfff0000000000000;

    un.d  = 1.0;
    un.v |= r;

    return un.d - 1.0;
}

#endif // need rand_double

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ! ___CRYPTORAND_H_401837192_1462841354__ */

/* EOF */
