#ifndef __ENCLAVE_KS_USER_H
#define __ENCLAVE_KS_USER_H

#include <iostream>
#include <string>

typedef enum INIT_STEP
{
    EMPTY = 0,
    EXCHANGED = 1,
    INITED = 2
} INIT_STEP;

class User{
    public:
        void Exchange(const char* userpkeyHex, const char* sharedStr);
        void SetAccount(const char* account){ m_account.append(account); }

    private:
        std::string m_account;
        std::string m_shared;
        std::string m_userpkeyHex;

        INIT_STEP m_step = EMPTY;
};

#endif
