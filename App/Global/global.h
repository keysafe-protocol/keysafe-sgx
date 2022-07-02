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

#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "service_provider.h"
#include "remote_attestation_result.h"
#include "network_ra.h"

static void SAFE_FREE(void * ptr)
{
    if(NULL != ptr)
    {
        free(ptr);
        ptr = NULL;
    }
}

#define SEALED_DATA_FILE "seal_data_blob.txt"
#define ENCLAVE_NAME_KS "libenclave_ks.signed.so"

static const unsigned char IV[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
    ifs.read(reinterpret_cast<char *>(buf), bsize);
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
    ofs.write(reinterpret_cast<const char *>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

static int aes_gcm_encrypt(const unsigned char *key, int key_len,
                           const unsigned char *iv, int iv_len,
                           const unsigned char *plain_text, int plen,
                           unsigned char *CIPHERTEXT, int *outlen)
{
    int howmany = 0;
    const EVP_CIPHER *cipher;
    switch (key_len)
    {
    case 128:
        cipher = EVP_aes_128_gcm();
        break;
    case 192:
        cipher = EVP_aes_192_gcm();
        break;
    case 256:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        break;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    int len = 0;
    while (len <= plen - 128)
    {
        EVP_EncryptUpdate(ctx, CIPHERTEXT + len, &howmany, plain_text + len, 128);
        *outlen += howmany;
        len += 128;
    }
    EVP_EncryptUpdate(ctx, CIPHERTEXT + len, &howmany, plain_text + len, plen - len);
    *outlen += howmany;
    int success = EVP_EncryptFinal_ex(ctx, CIPHERTEXT, &howmany);
    *outlen += howmany;
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

static int aes_gcm_decrypt(const unsigned char *key, int key_len,
                           const unsigned char *iv, int iv_len,
                           const unsigned char *CIPHERTEXT, int ct_len,
                           unsigned char *outbuf, int *outlen)
{
    int howmany = 0;
    const EVP_CIPHER *cipher;
    switch (key_len)
    {
    case 128:
        cipher = EVP_aes_128_gcm();
        break;
    case 192:
        cipher = EVP_aes_192_gcm();
        break;
    case 256:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        break;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    int len = 0;
    while (len <= ct_len - 128)
    {
        EVP_DecryptUpdate(ctx, outbuf + len, &howmany, CIPHERTEXT + len, 128);
        *outlen += howmany;
        len += 128;
    }
    EVP_DecryptUpdate(ctx, outbuf + len, &howmany, CIPHERTEXT + len, ct_len - len);
    // EVP_DecryptUpdate(ctx, outbuf, &howmany, CIPHERTEXT, ct_len);
    *outlen += howmany;
    int success = EVP_DecryptFinal_ex(ctx, outbuf, &howmany);
    *outlen += howmany;
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
static void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if (!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

static void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if (!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if (response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t *p_msg2_body = (sgx_ra_msg2_t *)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if (response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                         p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                      "Response of type not supported %d\n",
                response->type);
    }
}

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(__cplusplus)
}
#endif

#endif
