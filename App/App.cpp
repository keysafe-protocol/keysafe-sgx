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

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}


static bool seal_and_save_data()
{
    sgx_enclave_id_t eid_seal = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    uint8_t *temp_sealed_buf = (uint8_t*)malloc(sealed_data_size);
    if(NULL == temp_sealed_buf)
    {
        std::cout<<"Seal and Save | out of memory"<<std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    sgx_status_t retval;
    ret = seal_data(eid_seal, &retval, temp_sealed_buf, sealed_data_size);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    if(write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size,0)==false)
    {
        std::cout<<"Failed to save the sealed data blob to \""<< SEALED_DATA_FILE<<"\""<<std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    free(temp_sealed_buf);
    sgx_destroy_enclave(eid_seal);

    std::cout<<"Sealing data succeeded."<<std::endl;
    return true;
}

static bool read_and_unseal_data()
{
    sgx_enclave_id_t eid_unseal = 0;
    // Load the enclave for unsealing
    sgx_status_t ret =SGX_ERROR_UNEXPECTED;

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = unseal_data(eid_unseal, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    free(temp_buf);
    sgx_destroy_enclave(eid_unseal);

    std::cout << "Unseal succeeded." << std::endl;
    return true;
}

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
