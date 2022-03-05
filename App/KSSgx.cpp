#include "KSSgx.h"

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
