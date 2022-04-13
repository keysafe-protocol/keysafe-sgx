#ifndef _TEST_H
#define _TEST_H

#include "sgx_urts.h"
#if defined(__cplusplus)
extern "C" {
#endif

void test_gen_key(sgx_enclave_id_t eid_t);
void test_encrypt(sgx_enclave_id_t eid_t, const char* str);
void test_rsa_decrypt(sgx_enclave_id_t eid_t);
void test_aes_decrypt(sgx_enclave_id_t eid_t, char * str);
uint8_t* test_seal_and_save_data(sgx_enclave_id_t eid_t, uint32_t* sealedSize);
void test_read_unseal_data(sgx_enclave_id_t eid_unseal, uint8_t* sealedBlob, uint32_t data_size);
void test_get_public_key(sgx_enclave_id_t eid_t);
void test_gen_gauth_secret(sgx_enclave_id_t eid_t);
void test_gen_rand_num(sgx_enclave_id_t eid_t);
char* test_out_public_key(sgx_enclave_id_t eid_t, char* userpkHex);

#if defined(__cplusplus)
}
#endif



#endif
