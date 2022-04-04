#ifndef _KS_ENCLAVE_SSL_FUNCS_H
#define _KS_ENCLAVE_SSL_FUNCS_H
#include <string>

#include "stdio.h"
#include "stdlib.h"
#include "ks_enclave_ssl_define.h"

char* Base64Encode(const char* input, int len, bool withc_new_line);
char* Base64Decode(const char * input, int length, bool with_new_line);

unsigned char* rsa_decrypt(EVP_PKEY* evp_key, unsigned char* in, size_t inlen);
unsigned char* rsa_encrypt(EVP_PKEY* evp_pkey, const char* str);

std::string rsa_pub_encrypt(const char* pKey, const char* data);

int FormatPubToPem(RSA * pRSA, std::string& base64);



int aes_gcm_encrypt(const unsigned char* key, int key_len,
                    const unsigned char* iv, int iv_len,
                    const unsigned char* plain_text, int plen,
                    unsigned char* CIPHERTEXT, int *outlen);


int aes_gcm_decrypt(const unsigned char* key, int key_len,
                     const unsigned char* iv, int iv_len,
                     const unsigned char* CIPHERTEXT, int ct_len,
                     unsigned char* outbuf, int *outlen);



#endif
