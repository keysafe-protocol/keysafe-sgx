#include <string>

#include "test.h"
#include "global.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"

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

void test_rsa_decrypt(sgx_enclave_id_t eid_t)
{
    std::string strSource = "source text,hello world";
    sgx_status_t ret, ret_val;
    ret = ec_decrypt(eid_t, &ret_val, (const char*)strSource.c_str());
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
    sgx_enclave_id_t eid_seal = eid_t;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_data_size = 0;
    ret = ec_get_sealed_data_size(eid_seal, &sealed_data_size);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        return;
    }

    uint8_t *temp_sealed_buf = (uint8_t*)malloc(sealed_data_size);
    if(NULL == temp_sealed_buf)
    {
        std::cout<<"Seal and Save | out of memory"<<std::endl;
        return;
    }

    sgx_status_t retval;
    ret = ec_seal_data(eid_seal, &retval, temp_sealed_buf, sealed_data_size);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_sealed_buf);
        return;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_sealed_buf);
        return;
    }

    if(write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size,0)==false)
    {
        std::cout<<"Failed to save the sealed data blob to \""<< SEALED_DATA_FILE<<"\""<<std::endl;
        free(temp_sealed_buf);
        return;
    }
    free(temp_sealed_buf);

    std::cout<<"Sealing data succeeded."<<std::endl;
    return;
}


void test_read_unseal_data(sgx_enclave_id_t eid_unseal)
{
    // Load the enclave for unsealing
    sgx_status_t ret =SGX_ERROR_UNEXPECTED;

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
        return;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        return;
    }
    if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_buf);
        return;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = ec_unseal_data(eid_unseal, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        return;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_buf);
        return;
    }

    free(temp_buf);

    std::cout << "Unseal succeeded." << std::endl;
    return;

}
