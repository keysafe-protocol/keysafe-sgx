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
#include "global.h"

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
        void RegisterGauth();
        void RemoteAttestation();

    private:
        std::string user_hex;
        std::string enclave_hex;
        std::string shared;
        std::string account;
        EC_KEY *ec_pkey = NULL;
        EC_GROUP* group = NULL;
        char* ec_pkey_hex = NULL;

        ra_samp_request_header_t *p_msg0_full = NULL;
        ra_samp_response_header_t *p_msg0_resp_full = NULL;
        ra_samp_request_header_t *p_msg1_full = NULL;
        ra_samp_response_header_t *p_msg2_full = NULL;
        sgx_ra_msg3_t *p_msg3 = NULL;
        sgx_ra_context_t context = INT_MAX;
        ra_samp_request_header_t *p_msg3_full = NULL;
        ra_samp_response_header_t *p_att_result_msg_full = NULL;
        sgx_att_key_id_t selected_key_id = {0};
        sgx_status_t status = SGX_SUCCESS;
    

        void raCleanup();
};

#endif
