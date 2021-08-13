#ifndef __CIPHER_H__5071821__
#define __CIPHER_H__5071821__ 1

/*
 * Helper functions to select AES-256-CTR or Chacha20 cipher
 * for the random number generator.
 */

#include "aes.h"
#include "chacha_private.h"

#include "cryptorand.h"


static inline void
__chacha_key_setup(crypto_rand_state *st, uint8_t *key, uint8_t *iv)
{
    chacha_keysetup(&st->chacha, key, ARC4R_KEYSZ * 8, 0);
    chacha_ivsetup(&st->chacha,  iv);
}

static void
__chacha_crypt_buf(crypto_rand_state *st)
{
    chacha_encrypt_bytes(&st->chacha, st->buf, st->buf, sizeof st->buf);
}

static void
__chacha_rekey(crypto_rand_state *st)
{
    uint8_t rnd[ARC4R_KEYSZ + ARC4R_IVSZ];

    int r = (*st->entropy)(rnd, sizeof rnd);
    assert(r == 0);

    _rs_rekey(st, rnd, sizeof(rnd));
}


static void
__chacha_reinit(crypto_rand_state *st)
{
    uint8_t *key = &st->buf[0];
    uint8_t *iv  = key + ARC4R_KEYSZ;

    __chacha_key_setup(st, key, iv);

    // erase the key & iv, reduce the amount of rand we have
    memset(key, 0, ARC4R_KEYSZ + ARC4R_IVSZ);
    st->ptr = st->buf + (ARC4R_KEYSZ + ARC4R_IVSZ);
}

// one time initialization function for chacha20 cipher based rand
static inline void
__chacha_init(crypto_rand_state *st)
{
    uint8_t rnd[ARC4R_KEYSZ + ARC4R_IVSZ];

    // We expect to see at least 64 bytes of entropy when the
    // state is setup.
    int r = (*st->entropy)(rnd, sizeof rnd);
    assert(r == 0);

    // setup the state
    __chacha_key_setup(st, rnd, rnd+ARC4R_KEYSZ);
}


/*
 * Helper functions for AES cipher
 */
static inline void
__aes_key_setup(crypto_rand_state *st, uint8_t *key, uint8_t *iv)
{
    AES_init_ctx_iv(&st->aes, key, iv);
}

static void
__aes_crypt_buf(crypto_rand_state *st)
{
    AES_CTR_xcrypt_buffer(&st->aes, st->buf, sizeof st->buf);
}


static void
__aes_rekey(crypto_rand_state *st)
{
    uint8_t rnd[AESRAND_KEYSZ + AESRAND_IVSZ];

    int r = (*st->entropy)(rnd, sizeof rnd);
    assert(r == 0);

    _rs_rekey(st, rnd, sizeof(rnd));
}


static void
__aes_reinit(crypto_rand_state *st)
{
    uint8_t *key = &st->buf[0];
    uint8_t *iv  = key + AESRAND_KEYSZ;

    __aes_key_setup(st, key, iv);

    // erase the key & iv, reduce the amount of rand we have
    memset(key, 0, AESRAND_KEYSZ + AESRAND_IVSZ);
    st->ptr = st->buf + (AESRAND_KEYSZ + AESRAND_IVSZ);
}


// one time initialization function for aes-ctr cipher based rand
static inline void
__aes_init(crypto_rand_state *st)
{
    uint8_t rnd[AESRAND_KEYSZ + AESRAND_IVSZ];

    // We expect to see at least 64 bytes of entropy when the
    // state is setup.
    int r = (*st->entropy)(rnd, sizeof rnd);
    assert(r == 0);

    __aes_key_setup(st, rnd, rnd + AESRAND_KEYSZ);
}

#endif // __CIPHER_H__5071821__
