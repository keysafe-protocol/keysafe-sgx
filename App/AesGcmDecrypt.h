#ifndef __AES_GCM_DECRYPT_H
#define __AES_GCM_DECRYPT_H

#include <iostream>
#include "global.h"

class AesGcmDecrypt{
    public:
        static AesGcmDecrypt* Create(const unsigned char* shared, const unsigned char* cipher_text, int cipher_len);

    public:
        AesGcmDecrypt()
        {
            data = NULL;
        }
        AesGcmDecrypt(const unsigned char* shared, const unsigned char* cipher_text, int cipher_len)
        {
            this->capacity = (cipher_len/16+1)*16;
            this->data = (uint8_t*)malloc(this->capacity);
            aes_gcm_decrypt(shared, 256, IV, sizeof(IV),
                    cipher_text, cipher_len, this->data, &this->size);
            this->isDecrypted = true;
        }

        virtual ~AesGcmDecrypt()
        {
            if(isDecrypted && NULL != data)
            {
                free(data);
                data = NULL;
            }
        }

        int capacity = 0;
        int size = 0;
        uint8_t* data = NULL;
        bool isDecrypted = false;
};
#endif
