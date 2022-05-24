#ifndef __APP_U_USER_H
#define __APP_U_USER_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#include <string>

class UUser
{
    private:
        bool generate_key();

    public:
        UUser();
        UUser(char* szAccount){
            account.append(szAccount);
        }
        ~UUser();

        bool init();
        void auth();
        void RegisterMail();

    private:
        std::string user_hex;
        std::string enclave_hex;
        std::string shared;
        std::string account;
        EC_KEY *ec_pkey = NULL;
        EC_GROUP* group = NULL;
        char* ec_pkey_hex = NULL;
};

#endif
