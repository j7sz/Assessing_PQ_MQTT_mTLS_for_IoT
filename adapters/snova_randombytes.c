#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pico/rand.h"

int randombytes(unsigned char *out, unsigned long long outlen) {
    size_t len = (size_t)outlen;
    while (len >= sizeof(uint64_t)) {
        uint64_t value = get_rand_64();
        memcpy(out, &value, sizeof(value));
        out += sizeof(value);
        len -= sizeof(value);
    }
    if (len) {
        uint64_t value = get_rand_64();
        memcpy(out, &value, len);
    }
    return 0;
}
