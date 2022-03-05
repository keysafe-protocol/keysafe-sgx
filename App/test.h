#ifndef _TEST_H
#define _TEST_H

#include "sgx_urts.h"
#if defined(__cplusplus)
extern "C" {
#endif

void test_gen_key(sgx_enclave_id_t eid_t);
void test_rsa_decrypt(sgx_enclave_id_t eid_t);

#if defined(__cplusplus)
}
#endif



#endif
