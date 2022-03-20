#include <string>

#include "test.h"
#include "global.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"


void test_out_public_key(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    char* str = (char*)malloc(1024);
    ret = ec_ks_exchange(eid_t,&ret_val, str);
    printf("%s\n", str);
    free(str);
    //ret = ec_rand_num(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }

}


void test_gen_rand_num(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    //ret = ec_rand_num(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_gen_key(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    ret = ec_gen_key(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}


void test_encrypt(sgx_enclave_id_t eid_t, const char* str)
{
    sgx_status_t ret, ret_val;
    ret = ec_rsa_encrypt(eid_t, &ret_val, str);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_rsa_decrypt(sgx_enclave_id_t eid_t)
{
    std::string strSource = "source text,hello world";
    sgx_status_t ret, ret_val;
    ret = ec_rsa_decrypt(eid_t, &ret_val, (const char*)strSource.c_str());
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_seal_and_save_data(sgx_enclave_id_t eid_t)
{
}


void test_read_unseal_data(sgx_enclave_id_t eid_unseal)
{
}

void test_get_public_key(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    ret = ec_deliver_public_key(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}
