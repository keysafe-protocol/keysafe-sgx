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

#include "sgx_urts.h"
#include "Global/global.h"
#include "Enclave_KS_u.h"
#include "KSSgx.h"
#include "test.h"
#include "oc_funcs.h"
#include "ErrorSupport.h"

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
