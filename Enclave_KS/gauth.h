#ifndef _ENCLAVE_KS_GAUTH_H
#define _ENCLAVE_KS_GAUTH_H

#include "stdio.h"
#include "stdlib.h"
#include <stdint.h>

#define SECRET                    "/.google_authenticator"
#define SECRET_BITS               128         // Must be divisible by eight
#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define SCRATCHCODES              5           // Default number of initial scratchcodes
#define MAX_SCRATCHCODES          10          // Max number of initial scratchcodes
#define SCRATCHCODE_LENGTH        8           // Eight digits per scratchcode
#define BYTES_PER_SCRATCHCODE     4           // 32bit of randomness is enough
#define BITS_PER_BASE32_CHAR      5           // Base32 expands space by 8/5


#ifdef __cplusplus
extern "C"{
#endif

int generateCode(const char *key, unsigned long tm);

#ifdef __cplusplus
}
#endif

#endif