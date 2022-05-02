#include "gauth.h"
#include <time.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

int generateCode(const char *key, unsigned long tm){
    uint8_t challenge[8];
    for (int i = 8; i--; tm >>= 8)
    {
        challenge[i] = tm;
    }

    // Estimated number of bytes needed to represent the decoded secret. Because
    // of white-space and separators, this is an upper bound of the real number,
    // which we later get as a return-value from base32_decode()
    int secretLen = (strlen(key) + 7) / 8 * BITS_PER_BASE32_CHAR;

    // Sanity check, that our secret will fixed into a reasonably-sized static
    // array.
    if (secretLen <= 0 || secretLen > 100)
    {
        return -1;
    }

    // Decode secret from Base32 to a binary representation, and check that we
    // have at least one byte's worth of secret data.
    uint8_t secret[100];
    if ((secretLen = base32_decode((const uint8_t *)key, secret, secretLen)) < 1)
    {
        return -1;
    }

    // Compute the HMAC_SHA1 of the secret and the challenge.
    uint8_t hash[SHA1_DIGEST_LENGTH];
    hmac_sha1(secret, secretLen, challenge, 8, hash, SHA1_DIGEST_LENGTH);

    // Pick the offset where to sample our hash value for the actual verification
    // code.
    const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;

    // Compute the truncated hash in a byte-order independent loop.
    unsigned int truncatedHash = 0;
    for (int i = 0; i < 4; ++i)
    {
        truncatedHash <<= 8;
        truncatedHash |= hash[offset + i];
    }

    // Truncate to a smaller number of digits.
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= VERIFICATION_CODE_MODULUS;
    return truncatedHash;
}
