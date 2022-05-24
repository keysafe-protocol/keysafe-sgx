#ifndef __AES_GCM_ENCRYPT_H
#define __AES_GCM_ENCRYPT_H

#include <iostream>

class AesGcmEncrypt{
    public:
        static AesGcmEncrypt* Create(const unsigned char* shared, const unsigned char* cipher_text, int cipher_len);
    public:
        virtual ~AesGcmEncrypt()
        {
            if(isEncrypted)
            {
                free(data);
            }
            printf("AesGcmEncrypt Destroyed");
        }

        int capacity = 0;
        int size = 0;
        uint8_t* data = NULL;
        bool isEncrypted = false;
};
#endif
