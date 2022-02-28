#include <iostream>
#include <assert.h>
#include <fstream>
#include <thread>

#include "sgx_urts.h"
#include "Global/global.h"
#include "Enclave_KS_u.h"

#include "ErrorSupport.h"

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

static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if(ret != SGX_SUCCESS)
    {
        return ret;
    }
    return SGX_SUCCESS;
}

static bool test_init_enclave()
{
    sgx_enclave_id_t eid_ks = 0;
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_KS, &eid_ks);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }
    std::cout<<" Test Init Enclave successded."<<std::endl;
    return true;
}




int main(int argc, char* argv[])
{
    if(test_init_enclave() == false)
    {
        std::cout<<"test init enclave failed"<<std::endl;
        return -1;
    }
    return 0;
}
