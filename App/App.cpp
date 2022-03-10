#include <iostream>
#include <string>
#include <assert.h>
#include <fstream>
#include <thread>

#include "sgx_urts.h"
#include "Global/global.h"
#include "Enclave_KS_u.h"
#include "KSSgx.h"
#include "test.h"
#include "oc_funcs.h"
#include "ErrorSupport.h"


/*
EVP_PKEY *evp_pkey = NULL;
RSA *keypair = NULL;


void rsa_key_gen()
{
    BIGNUM *bn = BN_new();
    if (bn == NULL) {
        printf("BN_new failure: %ld\n", ERR_get_error());
        return;
    }
    int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
        printf("BN_set_word failure\n");
        return;
    }

    keypair = RSA_new();
    if (keypair == NULL) {
        printf("RSA_new failure: %ld\n", ERR_get_error());
        return;
    }
    ret = RSA_generate_key_ex(keypair, 3027, bn, NULL);
    if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
        return;
    }

    evp_pkey = EVP_PKEY_new();
    if (evp_pkey == NULL) {
        printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
        return;
    }
    EVP_PKEY_assign_RSA(evp_pkey, keypair);
    BN_free(bn);
}
*/

int main(int argc, char* argv[])
{
    auto instance = KSSgx::Instance();
    if(instance->initialize_enclave(ENCLAVE_NAME_KS))
    {
        sgx_enclave_id_t eid_t = instance->getEid();
        test_gen_key(eid_t);
        test_get_public_key(eid_t);
        //test_encrypt(eid_t, "please encrypte me");
    }
    delete instance;

    return 0;
}
