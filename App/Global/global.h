#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <iostream>
#include <string>
#include <cstring>
#include <fstream>

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

#include "stdio.h"
#include "stdlib.h"



#define SEALED_DATA_FILE "seal_data_blob.txt"
#define ENCLAVE_NAME_KS "libenclave_ks.signed.so"

static const unsigned char IV[] = {0,0,0,0,0,0,0,0,0,0,0,0};

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

static int aes_gcm_encrypt(const unsigned char* key, int key_len,
                    const unsigned char* iv, int iv_len,
                    const unsigned char* plain_text, int plen,
                    unsigned char* CIPHERTEXT, int *outlen)
{
   int howmany = 0;
    const EVP_CIPHER *cipher;
    switch(key_len)
    {
        case 128: cipher = EVP_aes_128_gcm();break;
        case 192: cipher = EVP_aes_192_gcm();break;
        case 256: cipher = EVP_aes_256_gcm();break;
        default:break;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    int len = 0;
    while(len <= plen - 128)
    {
        EVP_EncryptUpdate(ctx, CIPHERTEXT+len, &howmany, plain_text+len, 128);
        *outlen += howmany;
        len += 128;
    }
    EVP_EncryptUpdate(ctx, CIPHERTEXT + len, &howmany, plain_text + len, plen - len);
    *outlen += howmany;
    int success = EVP_EncryptFinal_ex(ctx,CIPHERTEXT, &howmany);
    *outlen += howmany;
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

static int aes_gcm_decrypt(const unsigned char* key, int key_len,
                     const unsigned char* iv, int iv_len,
                     const unsigned char* CIPHERTEXT, int ct_len,
                     unsigned char* outbuf, int *outlen)
{
     int howmany = 0;
    const EVP_CIPHER *cipher;
    switch(key_len)
    {
        case 128: cipher = EVP_aes_128_gcm();break;
        case 192: cipher = EVP_aes_192_gcm();break;
        case 256: cipher = EVP_aes_256_gcm();break;
        default:break;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    int len = 0;
    while(len <= ct_len - 128)
    {
        EVP_DecryptUpdate(ctx, outbuf+len, &howmany, CIPHERTEXT+len, 128);
        *outlen += howmany;
        len +=128;
    }
    EVP_DecryptUpdate(ctx, outbuf+len, &howmany, CIPHERTEXT+len, ct_len-len);
    //EVP_DecryptUpdate(ctx, outbuf, &howmany, CIPHERTEXT, ct_len);
    *outlen += howmany;
    int success = EVP_DecryptFinal_ex(ctx, outbuf, &howmany);
    *outlen += howmany;
    EVP_CIPHER_CTX_free(ctx);
    return success;
}






#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#endif
