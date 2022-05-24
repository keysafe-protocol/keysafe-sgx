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
#include "oc_funcs.h"
#include "ErrorSupport.h"
#include "UUser.h"


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


int main(int argc, char* argv[])
{
    auto instance = KSSgx::Instance();
    if(instance->initialize_enclave(ENCLAVE_NAME_KS))
    {
        instance->gen_ecc_key();
        auto user = new UUser("childmercy@163.com");
        user->init();
        user->auth();
        user->RegisterMail();
        user->RegisterGauth();
        printf("success\n");
    }
    delete instance;

    return 0;
}
