
platform := $(shell uname)

OpenBSD_objs = 
Linux_objs = posix_entropy.o
Darwin_objs = posix_entropy.o

objs = cryptorand.o aes.o error.o $($(platform)_objs)

tests = t_aesrand t_aesrand_bench t_arc4rand t_arc4rand_bench


Darwin_ldflags =
OpenBSD_ldflags = -lpthread
Linux_ldflags = -lpthread

CC = gcc
CFLAGS = -O3 -Wall -D__$(platform)__=1 -I.
LDFLAGS = $($(platform)_ldflags)

all: $(tests)

t_aesrand: t_aesrand.o $(objs)
	$(CC) -o $@ $^ $(LDFLAGS)

t_aesrand_bench: t_aesrand_bench.o $(objs)
	$(CC) -o $@ $^ $(LDFLAGS)

t_arc4rand: t_arc4rand.o $(objs)
	$(CC) -o $@ $^ $(LDFLAGS)

t_arc4rand_bench: t_arc4rand_bench.o $(objs)
	$(CC) -o $@ $^ $(LDFLAGS)
.PHONY: clean

clean:
	-rm -f $(objs) *.o $(tests)


