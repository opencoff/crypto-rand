# crypto-rand
This is a thread-safe adaptation of OpenBSD arc4random(2)
cryptographic random generator but generalized to use
AES-256-CTR or Chacha20 ciphers.

Both cryptographic random generators pass NIST-SP800-22 (Rev 1a).

## Using the API
The core of the code is in `cryptorand.c` and the API is documented
in `cryptorand.h`.

## Testing and Performance
The NIST-SP800-22 test suite is [here](https://github.com/dj-on-github/sp800_22_tests.git).

To run the NIST-SP800-2 tests, first fetch the test-suite from
github:

    git clone https://github.com/dj-on-github/sp800_22_tests.git

    make
    ./t_arc4rand 1048576 > arc4
    ./t_aesrand 1048576 > aes

    cd sp800_22_tests
    ./sp800_22_tests.py ../arc4
    ./sp800_22_tests.py ../aes


There are also a couple of benchmarks to measure speed of the
generators against the system's random generator (/dev/urandom):


        ./t_arc4rand_bench 16 32 64 128
        ./t_aesrand_bench  16 32 64 128

The benchmarks show the speed-up of the generators relative to the
system's random generator.

The core random generator should be quite portable to any system
(including RTOS). It only uses C stdlib and no stdio. The repository
includes portable implementations of AES and Chacha20. The cipher
specific code is separated into `cipher.h`. If your platform
provides HW accelerated AES, it is quite easy to plug that into this
generator.


## How is it licensed?
I don't have any special licensing terms; my changes are subject to
the original licensing terms in the file `cryptorand.c`.

