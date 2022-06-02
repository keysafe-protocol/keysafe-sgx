#ifndef __AES_GCM_ENCRYPT_H
#define __AES_GCM_ENCRYPT_H

#include <iostream>
#include "global.h"

class AesGcmEncrypt{
    public:
        static AesGcmEncrypt* Create(const unsigned char* shared, const unsigned char* cipher_text, int cipher_len);

    public:
        AesGcmEncrypt()
        {
            data = NULL;
        }

        AesGcmEncrypt(const unsigned char* shared, const unsigned char* cipher_text, int cipher_len)
        {
            this->capacity = (cipher_len/16+1)*16;
            this->data = (uint8_t*)malloc(this->capacity);
            aes_gcm_encrypt(shared, 256, IV, sizeof(IV),
                    cipher_text, cipher_len, this->data, &this->size);
            this->isEncrypted = true;
        }

        virtual ~AesGcmEncrypt()
        {
            if(isEncrypted && NULL != data)
            {
                free(data);
                data = NULL;
            }
        }

        int capacity = 0;
        int size = 0;
        uint8_t* data = NULL;
        bool isEncrypted = false;
};
#endif
