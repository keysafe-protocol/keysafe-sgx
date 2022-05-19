#include "KSSgx.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"

KSSgx* KSSgx::mInstance = NULL;

KSSgx* KSSgx::Instance()
{
    if(mInstance == NULL)
    {
        mInstance = new KSSgx();
    }
    return mInstance;
}
bool KSSgx::initialize_enclave(const char *szPath)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(szPath, SGX_DEBUG_FLAG,NULL, NULL, &mEid, NULL);
    if(ret != SGX_SUCCESS)
    {
        return false;
    }
    return true;
}

void KSSgx::gen_ecc_key()
{
    sgx_status_t ret, ret_val;
    ret = ec_gen_key(mEid, &ret_val);
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
