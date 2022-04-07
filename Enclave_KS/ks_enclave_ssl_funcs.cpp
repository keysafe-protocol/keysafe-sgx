#include "ks_enclave_ssl_funcs.h"
#include "ks_enclave_util.h"

#include <string>

char * Base64Encode(const char * input, int length, bool with_new_line)
{
    BIO * bmem = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char * buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);

    return buff;
}

char * Base64Decode(char * input, int length, bool with_new_line)
{
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        }
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

unsigned char* rsa_decrypt(EVP_PKEY* evp_pkey, unsigned char* in, size_t inlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pkey, evp_pkey->engine);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t outlen;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen);
    unsigned char* out = (unsigned char*)OPENSSL_malloc(outlen);
    EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen);
    printf("decrypt success : %s\n", out);
    return out;
}


unsigned char* rsa_encrypt(EVP_PKEY* evp_pkey, const char* str)
{
    std::string source;
    source.append(str);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pkey, evp_pkey->engine);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t outlen;
    const unsigned char *in = (unsigned char*)source.c_str();
    if(EVP_PKEY_encrypt(ctx, NULL, &outlen, in, source.length())<=0)
    {
        printf("encrypt failed\n");
        return NULL;
    }
    unsigned char* out = (unsigned char*)malloc(outlen+1);
    EVP_PKEY_encrypt(ctx, out, &outlen, in, source.length());
    return out;
}


std::string rsa_pub_encrypt(const char* pKey, const char* data)
{
    std::string strRet;
    RSA* rsa = RSA_new();
    BIO* keybio = BIO_new_mem_buf((unsigned char*)pKey, -1);
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

    int len = RSA_size(rsa);
    char* encryptText = (char*)malloc(len + 1);
    memset(encryptText, 0, len+1);

    int ret = RSA_public_decrypt(strlen(data), (const unsigned char*)data, (unsigned char*)encryptText, rsa, RSA_PKCS1_PADDING);
    if(ret >0)
    {
        strRet = std::string(encryptText, ret);
    }
    free(encryptText);
    BIO_free_all(keybio);
    RSA_free(rsa);
    return strRet;
}

int FormatPubToPem(RSA * pRSA, std::string& base64)
{
    base64.clear();
    BUF_MEM *pBMem = NULL;
    BIO *pBIO = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSAPublicKey(pBIO,pRSA) !=1)
    {
        printf("public key error\n");
    }
    BIO_get_mem_ptr(pBIO, &pBMem);
    base64.append(pBMem->data,pBMem->length);
    BIO_free(pBIO);
    return 0;
}


int aes_gcm_encrypt(const unsigned char* key, int key_len,
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

int aes_gcm_decrypt(const unsigned char* key, int key_len,
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

