#include <string>

#include "test.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"

void test_gen_key(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    ret = gen_key(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
    }
}

void test_rsa_decrypt(sgx_enclave_id_t eid_t)
{
    std::string strSource = "source text,hello world";
    sgx_status_t ret, ret_val;
    ret = ic_decrypt(eid_t, &ret_val, (const char*)strSource.c_str());
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
    }
    else if(ret_val != SGX_SUCCESS)
    {
            ret_error_support(ret_val);
    }
}
