#ifndef __AES_GCM_ENCRYPT_H
#define __AES_GCM_ENCRYPT_H

#include <iostream>

class AesGcmDecrypt{
    public:
        static AesGcmDecrypt* Create(const unsigned char* shared, const unsigned char* cipher_text, int cipher_len);
    public:
        virtual ~AesGcmDecrypt()
        {
            if(isDecrypted)
            {
                free(data);
            }
            std::cout<<"decrypted destoryed"<<std::endl;
        }

        int capacity = 0;
        int size = 0;
        uint8_t* data = NULL;
        bool isDecrypted = false;
};
#endif
