#include <map>
#include <string>
#include <iostream>

#include "ks_enclave_ssl_funcs.h"
#include "ks_enclave_util.h"
#include "Enclave_KS_t.h"
#include "tSgxSSL_api.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "gauth.h"
#include "base32.h"
#include "KSSpinLock.h"

#define ADD_ENTROPY_SIZE 32

static const unsigned char IV[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static sgx_spinlock_t ks_op_spin_lock = SGX_SPINLOCK_INITIALIZER;

EVP_PKEY *evp_pkey = NULL;
RSA *keypair = NULL;
std::string base64PublicKey;
int nPublicLength = 0;
std::map<int, std::string> recoveryMap;
std::map<std::string, int> secretMap;
char shared[256];

EC_KEY *ec_pkey = NULL;
EC_GROUP *group = NULL;
char *ec_pkey_hex = NULL;

sgx_sealed_data_t *seal_data(uint8_t *data, uint32_t len, uint32_t *sealed_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, len);
    if (sealed_data_size == UINT32_MAX)
    {
        printf("sealed_data_size out of range\n");
        return NULL;
    }

    sgx_sealed_data_t *temp_sealed_buff = (sgx_sealed_data_t *)malloc(sealed_data_size);
    if (temp_sealed_buff == NULL)
    {
        return NULL;
    }

    sgx_status_t err = sgx_seal_data(0, NULL, len, data,
                                                                sealed_data_size,
                                                                (sgx_sealed_data_t *)temp_sealed_buff);
    if(err != SGX_SUCCESS)
    {
        printf("seal_data | seal failed\n");
        return NULL;
    }
    *sealed_size = sealed_data_size;
    return temp_sealed_buff;
}

uint8_t* unseal_data(uint8_t* sealed_data, uint32_t* decrypt_data_len)
{
    uint32_t mac_text_len = 0;
    *decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_data);
    uint8_t* decrypt_data = (uint8_t*)malloc(*decrypt_data_len);

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t*)sealed_data, NULL, &mac_text_len,
                                                                    decrypt_data, decrypt_data_len);
    if(ret != SGX_SUCCESS)
    {
        return NULL;
    }

    return decrypt_data;
}

sgx_status_t ec_gen_gauth_secret(uint8_t *secret, int len, uint8_t* encrypted_secret)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    uint8_t buf[SECRET_BITS / 8 + MAX_SCRATCHCODES * BYTES_PER_SCRATCHCODE];
    static const char hotp[] = "\" HOTP_COUNTER 1\n";
    static const char totp[] = "\" TOTP_AUTH\n";
    static const char disallow[] = "\" DISALLOW_REUSE\n";
    static const char step[] = "\" STEP_SIZE 30\n";
    static const char window[] = "\" WINDOW_SIZE 17\n";
    static const char ratelimit[] = "\" RATE_LIMIT 3 30\n";
    char s[(SECRET_BITS + BITS_PER_BASE32_CHAR - 1) / BITS_PER_BASE32_CHAR +
           1 /* newline */ +
           sizeof(hotp) + // hotp and totp are mutually exclusive.
           sizeof(disallow) +
           sizeof(step) +
           sizeof(window) +
           sizeof(ratelimit) + 5 + // NN MMM (total of five digits)
           SCRATCHCODE_LENGTH * (MAX_SCRATCHCODES + 1 /* newline */) +
           1 /* NUL termination character */];
    sgx_read_rand(buf, sizeof(buf));
    base32_encode(buf, SECRET_BITS / 8, (uint8_t *)s, sizeof(s));

    uint32_t sealed_size = 0;
    sgx_sealed_data_t* sealed_data = seal_data((uint8_t*)s, sizeof(s), &sealed_size);
    if(sealed_data == NULL)
        return SGX_ERROR_UNEXPECTED;

    memcpy(secret, sealed_data, sealed_size);
    free(sealed_data);

    int outLen = (sizeof(s)/16+1)*16;
    unsigned char* out = (unsigned char*)malloc(outLen);
    int count = 0;
    aes_gcm_encrypt((const unsigned char*)shared, 256,
                                    IV, sizeof(IV),
                                    (const unsigned char*)s, sizeof(s),
                                    out, &count);
    memcpy(encrypted_secret, out, count);
    free(out);
    return static_cast<sgx_status_t>(0);
}

uint32_t ec_check_code(uint8_t *sealed_secret, int len,
                                                    uint64_t tm, uint8_t* encrypted_code, int code_len,
                                                    uint8_t* sealed_data, int len2, char* chip)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    uint32_t data_len;
    uint8_t* out = unseal_data(sealed_secret, &data_len);
    if(out == NULL)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    int outLen = (code_len/16+1)*16;
    int count = 0;
    unsigned char*  decrypted_code = (unsigned char*)malloc(outLen);
    aes_gcm_decrypt((const unsigned char*)shared, 256, IV, sizeof(IV),
                                    encrypted_code, code_len,
                                    decrypted_code, &count);
    printf("decrypted code\n");
    printf("%s\n", decrypted_code);

    int code = atoi((const char*)decrypted_code);
    const unsigned long t = tm / 30;
    const int correct_code = generateCode((char *)out, t);
    free(out);
    if (code != correct_code)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(code == correct_code)
    {
        out = unseal_data(sealed_data, &data_len);
        int cipherlen = (data_len/16+1)*16;
        int count = 0;
        unsigned char* cipher = (unsigned char*)malloc(cipherlen + 1);
        aes_gcm_encrypt((const unsigned char*)shared, 256, IV, sizeof(IV),
                                            out, data_len,
                                            cipher, &count);


        memcpy(chip, cipher, count);
        free(out);
        free(cipher);
        return count;
    }
    return 0;
}

void ecc_key_gen()
{
    ec_pkey = EC_KEY_new();
    if (ec_pkey == NULL)
    {
        printf("%s\n", "EC_KEY_new err!");
        return;
    }
    int crv_len = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve *curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
    EC_get_builtin_curves(curves, crv_len);
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL)
    {
        printf("%s\n", "Group new failed");
        return;
    }

    unsigned int ret = EC_KEY_set_group(ec_pkey, group);
    if (ret != 1)
    {
        printf("%s\n", "EC_KEY_Set_group failed");
        return;
    }

    ret = EC_KEY_generate_key(ec_pkey);
    if (ret != 1)
    {
        printf("%s\n", "EC_KEY_generate_key failed");
        return;
    }

    ret = EC_KEY_check_key(ec_pkey);
    if (ret != 1)
    {
        printf("%s\n", "check key failed");
        return;
    }

    free(curves);
}

void rsa_key_gen()
{
    BIGNUM *bn = BN_new();
    if (bn == NULL)
    {
        printf("BN_new failure: %ld\n", ERR_get_error());
        return;
    }
    int ret = BN_set_word(bn, RSA_F4);
    if (!ret)
    {
        printf("BN_set_word failure\n");
        return;
    }

    keypair = RSA_new();
    if (keypair == NULL)
    {
        printf("RSA_new failure: %ld\n", ERR_get_error());
        return;
    }
    ret = RSA_generate_key_ex(keypair, 3027, bn, NULL);
    if (!ret)
    {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
        return;
    }

    evp_pkey = EVP_PKEY_new();
    if (evp_pkey == NULL)
    {
        printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
        return;
    }
    EVP_PKEY_assign_RSA(evp_pkey, keypair);

    BN_free(bn);
}

void deliver_public_key()
{
    std::string base64;
    FormatPubToPem(keypair, base64);
    // oc_deliver_public_key(base64.c_str());
}

char aad_mac_text[BUFSIZ] = "aad mac text";

sgx_status_t ec_gen_key()
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    // rsa_key_gen();
    ecc_key_gen();
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_deliver_public_key()
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    deliver_public_key();
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_rsa_encrypt(const char *from)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    char *out = (char *)rsa_encrypt(evp_pkey, from);
    std::string outStr;
    outStr.append(out);
    free(out);
    // oc_encrypted_string(outStr.c_str());
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_ks_exchange(char *userpkeyHex, char *enclaveHex, char *sharedStr)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    memset(shared, 0, sizeof(shared));
    printf("user hex \n");
    printf("%s\n", userpkeyHex);
    const EC_POINT *point = EC_KEY_get0_public_key(ec_pkey);
    ec_pkey_hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    // devliver the enclave ecc public key hex code
    memcpy(enclaveHex, ec_pkey_hex, strlen(ec_pkey_hex));

    EC_POINT *uPoint = EC_POINT_hex2point(group, userpkeyHex, NULL, NULL);
    int len = ECDH_compute_key(shared, 256, uPoint, ec_pkey, NULL);

    memcpy(sharedStr, shared, len);

    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_aes_gcm_encrypt(char *str)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_aes_gcm_decrypt(char *sharedStr, char *ciphertext)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    int inLen = strlen(ciphertext);
    int outLen = (inLen / 16 + 1) * 16;
    int oh = 0;
    unsigned char *out = (unsigned char *)malloc(outLen);
    memset(out, 0, outLen);
    aes_gcm_decrypt((unsigned char *)sharedStr, 256, IV, sizeof(IV),
                    (const unsigned char *)ciphertext, strlen(ciphertext),
                    out, &oh);
    // printf("%s\n", out);
    free(out);
    return static_cast<sgx_status_t>(0);
}

uint32_t ec_calc_sealed_size(uint32_t len)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    return sgx_calc_sealed_data_size(0, (uint32_t)len);
}

sgx_status_t ec_ks_seal(const char *str, int len, uint8_t *sealedStr, int sealedSize)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    int outLen = (len / 16 + 1) * 16;
    unsigned char *out = (unsigned char *)malloc(outLen);
    memset(out, 0, outLen);
    int outhowmany = 0;
    aes_gcm_decrypt((unsigned char *)shared, 256, IV, sizeof(IV),
                    (const unsigned char *)str, len,
                    out, &outhowmany);

    uint8_t *encrypt_data = (uint8_t *)malloc(outhowmany);
    memset(encrypt_data, 0, outhowmany);
    memcpy(encrypt_data, out, outhowmany);

    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)outhowmany);
    printf("seal data size %d\n", sealed_data_size);
    if (sealed_data_size == UINT32_MAX)
    {
        free(encrypt_data);
        free(out);
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_sealed_data_t *temp_sealed_buff = (sgx_sealed_data_t *)malloc(sealed_data_size);
    if (temp_sealed_buff == NULL)
    {
        printf("tem sealed new failed\n");
        free(out);
        free(temp_sealed_buff);
        free(encrypt_data);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t err = sgx_seal_data(0,
                                     NULL,
                                     outhowmany,
                                     encrypt_data,
                                     sealed_data_size,
                                     (sgx_sealed_data_t *)temp_sealed_buff);

    if (err == SGX_SUCCESS)
    {
        memcpy(sealedStr, temp_sealed_buff, sealed_data_size);
    }

    free(out);
    free(encrypt_data);
    free(temp_sealed_buff);

    return err;
}

uint32_t ec_ks_unseal2(const char* account,
                                        uint8_t* code_cipher, uint32_t cipher_code_len,
                                        uint8_t* condition, uint32_t conditon_size,
                                        uint8_t* sealed_data, uint32_t sealed_data_size,
                                        uint8_t* encrypted_unseal_data, uint32_t encrypted_unseal_data_size)
{
    return 0;
}

uint32_t ec_ks_unseal(const char *pkey, uint8_t *str, uint32_t data_size)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    printf("unseal start\n");
    uint32_t mac_text_len = 0;
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)str);

    printf("%ld %ld", data_size, decrypt_data_len);
    printf("\n");
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if (decrypt_data == NULL)
    {
        printf("decrypt_data malloc failed\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)str,
                                       NULL,
                                       &mac_text_len,
                                       decrypt_data,
                                       &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        printf("unseal failed\n");
        free(decrypt_data);
        return ret;
    }

    printf("unseal data\n");
    printf("%s", (char *)decrypt_data);
    printf("\n");

    uint32_t retVal = 0;
    unsigned char a[1];
    sgx_read_rand(a, 1);
    retVal = (int)a[0] * 100 + (int)a[1];

    std::string v;
    v.append((const char *)decrypt_data, decrypt_data_len);
    recoveryMap[retVal] = v;
    printf("random code\n");
    printf("%d\n", retVal);
    /*
    std::string encryptText = rsa_pub_encrypt(pkey, (const char*)decrypt_data);
    oc_deliver_unseal_string(encryptText.c_str());
    */

    free(decrypt_data);
    return retVal;
}

uint32_t ec_prove_me(uint8_t *key_pt, int klen, char * unsealStr)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    int outlen = (klen / 16 + 1) * 16;
    unsigned char *outbuf = (unsigned char *)malloc(outlen);
    memset(outbuf, 0, outlen);
    int khowmany = 0;
    aes_gcm_decrypt((unsigned char *)shared, 256,
                    IV, sizeof(IV),
                    (unsigned char *)key_pt, klen,
                    outbuf, &khowmany);
    printf("decrypt buf\n");
    printf("%s\n", outbuf);
    // int nKey = (int)outbuf[0]*100 + (int)outbuf[1];
    int nKey = atoi((char *)outbuf);
    printf("prove me nKey\n");
    printf("%d\n", nKey);
    free(outbuf);

    std::map<int, std::string>::iterator it = recoveryMap.find(nKey);
    if (it != recoveryMap.end())
    {
        std::string v = it->second;

        /*
        printf("prove me : before encrypt\n");
        printf("%s\n", v.c_str());
        */
        int outlen = (v.length() / 16 + 1) * 16;
        int ohowmany = 0;
        unsigned char *tmp = (unsigned char *)malloc(outlen);
        aes_gcm_encrypt((unsigned char *)shared, 256, IV, sizeof(IV),
                        (const unsigned char *)v.c_str(), v.length(),
                        tmp, &ohowmany);
        memcpy(unsealStr, tmp, ohowmany);
        // oc_deliver_unseal_string(v.c_str());
        recoveryMap.erase(nKey);
        free(tmp);
        return ohowmany;
    }
    else
    {
        printf("sealed data not found\n");
    }
    return 0;
}

sgx_status_t ec_rsa_decrypt(const char *str)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    std::string source(str);
    size_t outlen = source.length() + 1;
    rsa_decrypt(evp_pkey, (unsigned char *)source.c_str(), outlen);

    return static_cast<sgx_status_t>(0);
}

uint32_t ec_auth(const char* account, const char* userpkeyHex)
{
    return 0;
}

sgx_status_t ec_auth_confirm(const char* account, uint8_t* code_cipher, uint32_t cipher_len)
{
    return static_cast<sgx_status_t>(0);
}

uint32_t ec_gen_register_mail_code(const char* account, uint8_t* content, uint32_t content_len)
{
    return 0;
}

sgx_status_t ec_register_mail(const char* account, 
                                                    uint8_t* code_cipher, uint32_t cipher_code_len,
                                                    uint8_t* sealedStr, int sealedSize)
{
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_register_password(const char* account, 
                                                    uint8_t* code_cipher, uint32_t cipher_code_len,
                                                    uint8_t* sealedStr, int sealedSize)
{
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_register_gauth(const char* account, 
                                                    uint8_t* code_cipher, uint32_t cipher_code_len,
                                                    uint8_t* sealedStr, int sealedSize)
{
    return static_cast<sgx_status_t>(0);
}
