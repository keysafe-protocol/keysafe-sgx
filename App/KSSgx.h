#ifndef _KSSGX_H
#define _KSSGX_H

#include <iostream>
#include <string>

#include "sgx_urts.h"
class KSSgx
{
    private:
        KSSgx(){}

    public:
        virtual ~KSSgx(){
            sgx_destroy_enclave(mEid);
        }

        static KSSgx* Instance();
        bool initialize_enclave(const char *szPath);

    private:
        static KSSgx* mInstance;
        std::string mPublicKey;
        sgx_enclave_id_t mEid = 0;

    public:
        sgx_enclave_id_t getEid()
        {
            return mEid;
        }

        const char* getPublicKey()
        {
            return mPublicKey.c_str();
        }

        void InitPubKey(const char* str)
        {
            if(mPublicKey.empty() == false)
                mPublicKey.clear();
            mPublicKey.append(str);
        }
};

#endif
