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
    // Enclave_Seal: seal the secret and save the data blob to a file
    /*
    if (seal_and_save_data() == false)
    {
        std::cout << "Failed to seal the secret and save it to a file." << std::endl;
        return -1;
    }

    if(read_and_unseal_data() == false)
    {
        std::cout<<"Failed to unseal the data blob."<<std::endl;
        return -1;
    }
    */
    //test_gen_key();
    //test_rsa_decrypt();
    auto instance = KSSgx::Instance();
    if(instance->initialize_enclave(ENCLAVE_NAME_KS))
    {
        sgx_enclave_id_t eid_t = instance->getEid();
        test_gen_key(eid_t);
        test_rsa_decrypt(eid_t);
    }
    delete instance;

    return 0;
}
