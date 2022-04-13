#include <iostream>
#include <string>
#include <assert.h>
#include <fstream>
#include <thread>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#include "sgx_urts.h"
#include "Global/global.h"
#include "Enclave_KS_u.h"
#include "KSSgx.h"
#include "test.h"
#include "oc_funcs.h"
#include "ErrorSupport.h"


EC_KEY *ec_pkey = NULL;
EC_GROUP* group = NULL;
char* ec_pkey_hex = NULL;

void ecc_key_gen()
{
    ec_pkey= EC_KEY_new();
    if(ec_pkey == NULL)
    {
        printf("%s\n","EC_KEY_new err!");
        return;
    }
    int crv_len = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve *curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve)*crv_len);
    EC_get_builtin_curves(curves, crv_len);
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(group == NULL)
    {
        printf("%s\n", "Group new failed");
        return;
    }

    unsigned int ret = EC_KEY_set_group(ec_pkey, group);
    if(ret != 1)
    {
        printf("%s\n","EC_KEY_Set_group failed");
        return;
    }

    ret = EC_KEY_generate_key(ec_pkey);
    if(ret!=1)
    {
        printf("%s\n", "EC_KEY_generate_key failed");
        return;
    }

    ret = EC_KEY_check_key(ec_pkey);
    if(ret !=1)
    {
        printf("%s\n","check key failed");
        return;
    }

        free(curves);
}


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
        ecc_key_gen();
        const EC_POINT *point = EC_KEY_get0_public_key(ec_pkey);
        //char* ec_pkey_hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
        char* ec_pkey_hex = "0481e1394c8ffd5cb774ca37609ebbfc16d1a22498d210af155975c1070f4da581c2cb33d33b5dd24a25fd47fbd5460039ce4ce63197e6b789e92b565ccec452ca";

        sgx_enclave_id_t eid_t = instance->getEid();
        test_gen_key(eid_t);
        test_gen_gauth_secret(eid_t);
        /*
        if(NULL != enclavepkHex)
        {
            EC_POINT *uPoint = EC_POINT_hex2point(group, enclavepkHex, NULL, NULL);
            char shared[256];
            ECDH_compute_key(shared, 256, uPoint, ec_pkey, NULL);
            printf("e shared %s\n", shared);

            char oData[] = "hello world!!!!";
            AES_KEY aes;
            AES_set_encrypt_key((const unsigned char*)shared, 256, &aes);

            int inLen = strlen(oData);
            int outLen = (inLen/16+1)*16;
            unsigned char* out = (unsigned char*)malloc(outLen);
            AES_encrypt((const unsigned char*)oData, out, &aes);

            test_aes_decrypt(eid_t, (char*)out);

            uint32_t  sealedSize = 0;
            uint8_t* sealedBlob = test_seal_and_save_data(eid_t, &sealedSize);
            test_read_unseal_data(eid_t, sealedBlob, sealedSize);
            free(sealedBlob);

            free(enclavepkHex);
        }
    */
        printf("success\n");
    }
    delete instance;

    return 0;
}
