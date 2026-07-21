/* randombytes.c - PQClean expects the platform to provide randombytes().
 *
 * We back it with the Pico SDK's pico_rand. This is used by randomized signing
 * paths. Static key generation is performed off-device and is never timed.
 */
#include <string.h>
#include "pico/rand.h"
#include "randombytes.h"   /* PQClean prototype: int randombytes(uint8_t*, size_t) */

int randombytes(uint8_t *buf, size_t n) {
    while (n >= 8) {
        uint64_t r = get_rand_64();
        memcpy(buf, &r, 8);
        buf += 8;
        n   -= 8;
    }
    if (n) {
        uint64_t r = get_rand_64();
        memcpy(buf, &r, n);
    }
    return 0;
}
