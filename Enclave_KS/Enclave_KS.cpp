#include <map>
#include <string>
#include <iostream>

#include "ks_enclave_ssl_funcs.h"
#include "ks_enclave_util.h"
#include "Enclave_KS_t.h"
#include "tSgxSSL_api.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "gauth.h"
#include "base32.h"
#include "KSSpinLock.h"
#include "User.h"
#include "UserManager.h"

#define ADD_ENTROPY_SIZE 32

static const unsigned char IV[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

//static const sgx_ec256_public_t g_sp_pub_key = {{0}, {0}};
// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};

static sgx_spinlock_t ks_op_spin_lock = SGX_SPINLOCK_INITIALIZER;

EVP_PKEY *evp_pkey = NULL;
RSA *keypair = NULL;
std::string base64PublicKey;
int nPublicLength = 0;
std::map<int, std::string> recoveryMap;
std::map<std::string, int> secretMap;

EC_KEY *ec_pkey = NULL;
EC_GROUP *group = NULL;
char *ec_pkey_hex = NULL;

uint32_t gen_random_code()
{
    uint32_t retVal = 0;
    unsigned char a[1];
    sgx_read_rand(a, 1);
    retVal = (int)a[0] * 100 + (int)a[1];
    return retVal;
}

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
    if (err != SGX_SUCCESS)
    {
        printf("seal_data | seal failed\n");
        return NULL;
    }
    *sealed_size = sealed_data_size;
    return temp_sealed_buff;
}

uint8_t *unseal_data(uint8_t *sealed_data, uint32_t *decrypt_data_len)
{
    uint32_t mac_text_len = 0;
    *decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
    uint8_t *decrypt_data = (uint8_t *)malloc(*decrypt_data_len);

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_data, NULL, &mac_text_len,
                                       decrypt_data, decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        printf("unseal failed\n");
        return NULL;
    }

    return decrypt_data;
}

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context)
{
    sgx_ec256_public_t g_sp_pub_key;
    sgx_status_t ret;
    const EC_POINT *point = EC_KEY_get0_public_key(ec_pkey);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if(EC_POINT_get_affine_coordinates(group, point, x,y,NULL))
    {
        printf("\ntest 1 %d\n", BN_num_bytes(x)+1);
        BN_bn2lebinpad(x, (unsigned char*)g_sp_pub_key.gx, SGX_ECP256_KEY_SIZE);
        BN_bn2lebinpad(y,(unsigned char*)g_sp_pub_key.gy, SGX_ECP256_KEY_SIZE);
    }
    else{
        printf("test 2\n");
        BN_free(x);
        BN_free(y);
        return SGX_ERROR_UNEXPECTED;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    return ret;
}

sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}

sgx_status_t ec_gen_gauth_secret(uint8_t *secret, int len, uint8_t *encrypted_secret)
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
           1 +
           sizeof(hotp) + // hotp and totp are mutually exclusive.
           sizeof(disallow) +
           sizeof(step) +
           sizeof(window) +
           sizeof(ratelimit) + 5 + // NN MMM (total of five digits)
           SCRATCHCODE_LENGTH * (MAX_SCRATCHCODES + 1) +
           1];
    sgx_read_rand(buf, sizeof(buf));
    base32_encode(buf, SECRET_BITS / 8, (uint8_t *)s, sizeof(s));

    uint32_t sealed_size = 0;
    sgx_sealed_data_t *sealed_data = seal_data((uint8_t *)s, sizeof(s), &sealed_size);
    if (sealed_data == NULL)
        return SGX_ERROR_UNEXPECTED;

    memcpy(secret, sealed_data, sealed_size);
    free(sealed_data);

    /*
    int outLen = (sizeof(s)/16+1)*16;
    unsigned char* out = (unsigned char*)malloc(outLen);
    int count = 0;
    aes_gcm_encrypt((const unsigned char*)shared, 256,
            IV, sizeof(IV),
            (const unsigned char*)s, sizeof(s),
            out, &count);
    */
    memcpy(encrypted_secret, s, sizeof(s));
    return static_cast<sgx_status_t>(0);
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

sgx_status_t ec_ks_exchange(char *userpkeyHex, char *enclaveHex, char *sharedStr)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    if (UserManager::Instance()->ExchangeUserExisted(userpkeyHex))
    {
        printf("exchange user existed\n");
        const EC_POINT *point = EC_KEY_get0_public_key(ec_pkey);
        ec_pkey_hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
        memcpy(enclaveHex, ec_pkey_hex, strlen(ec_pkey_hex));

        return static_cast<sgx_status_t>(0);
    }
    else
    {
        printf("exchange user is new\n");
        char shared[256];
        memset(shared, 0, sizeof(shared));
        const EC_POINT *point = EC_KEY_get0_public_key(ec_pkey);
        ec_pkey_hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
        memcpy(enclaveHex, ec_pkey_hex, strlen(ec_pkey_hex));

        EC_POINT *uPoint = EC_POINT_hex2point(group, userpkeyHex, NULL, NULL);
        int len = ECDH_compute_key(shared, 256, uPoint, ec_pkey, NULL);

        User user;
        user.Exchange(userpkeyHex, shared);
        UserManager::Instance()->PushExchangeUser(userpkeyHex, user);
        memcpy(sharedStr, shared, len);
    }

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

sgx_status_t ec_ks_seal(const char *account, const char *str, int len, uint8_t *sealedStr, int sealedSize)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    const char *shared = UserManager::Instance()->GetShared(account);

    if (NULL == shared)
    {
        printf("ec_register_gauth failed : account not exist\n");
        return SGX_ERROR_UNEXPECTED;
    }

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

uint32_t ec_ks_unseal_gauth(const char *account,
                            uint8_t *code_cipher, uint32_t cipher_code_len,
                            uint64_t tm,
                            uint8_t *condition, uint32_t condition_size,
                            uint8_t *sealed_data, uint32_t sealed_data_size,
                            uint8_t *encrypted_unseal_data)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    const char *shared = UserManager::Instance()->GetShared(account);

    if (NULL == shared)
    {
        printf("ec_ks_unseal4gauth failed : account not exist\n");
        return 0;
    }

    int outLen = (cipher_code_len / 16 + 1) * 16;
    int len = 0;
    uint8_t *buff = (uint8_t *)malloc(outLen);
    aes_gcm_decrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    code_cipher, cipher_code_len,
                    buff, &len);
    int code = atoi((char *)buff);
    free(buff);

    outLen = (condition_size / 16 + 1) * 16;
    len = 0;
    uint8_t *secret = (uint8_t *)malloc(outLen);
    aes_gcm_decrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    condition, condition_size,
                    secret, &len);

    const unsigned long t = tm / 30;
    const int correct_code = generateCode((char *)secret, t);
    free(secret);

    if (code != correct_code)
    {
        printf("ec_ks_unseal4gauth failed : code not equal\n");
        return 0;
    }

    uint32_t unseal_size = 0;
    uint8_t *out = unseal_data(sealed_data, &unseal_size);
    if (out == NULL)
    {
        printf("ec_ks_unseal4gauth failed : unseal error\n");
        return 0;
    }

    int eLen = (unseal_size / 16 + 1) * 16;
    len = 0;
    buff = (uint8_t *)malloc(eLen);
    aes_gcm_encrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    out, unseal_size, buff, &len);
    memcpy(encrypted_unseal_data, buff, len);
    free(buff);

    return len;
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

    free(decrypt_data);
    return retVal;
}

uint32_t ec_auth(const char *account, const char *userpkeyHex)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    if (!UserManager::Instance()->ExchangeUserExisted(userpkeyHex))
    {
        printf("ec_auth failed : userpkeyhex not found");
        printf("%s\n", userpkeyHex);
        return 0;
    }

    if (UserManager::Instance()->PushAvaliableUser(account, userpkeyHex))
    {
        uint32_t code = gen_random_code();
        std::string strUserPkeyHex;
        strUserPkeyHex.append(userpkeyHex);
        UserManager::Instance()->PushUserIndexMap(code, strUserPkeyHex);
        return code;
    }
    else
    {
        printf("PushAvaliableUser failed\n");
    }
    return 0;
}

sgx_status_t ec_auth_confirm(const char *account, uint8_t *code_cipher, uint32_t cipher_len)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    const char *shared = UserManager::Instance()->GetShared(account);
    if (NULL == shared)
    {
        printf("ec_auth_confirm : failed, shared not existed\n");
        return SGX_ERROR_UNEXPECTED;
    }

    int outLen = (cipher_len / 16 + 1) * 16;
    int outhowmany = 0;
    uint8_t *outbuf = (uint8_t *)malloc(outLen);
    aes_gcm_decrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    (const unsigned char *)code_cipher, cipher_len,
                    outbuf, &outhowmany);

    std::string sc(outbuf, outbuf + outhowmany);
    int code = 0;
    code = atoi(sc.c_str());
    free(outbuf);

    if (false == UserManager::Instance()->UserIndexExisted(code))
    {
        UserManager::Instance()->RemoveAvaliableUser(account);
        UserManager::Instance()->RemoveUserIndex(code);
        printf("ec_auth_confirm : failed, code not existed\n");

        return SGX_ERROR_UNEXPECTED;
    }
    UserManager::Instance()->RemoveUserIndex(code);

    return static_cast<sgx_status_t>(0);
}

uint32_t ec_gen_register_mail_code(const char *account, uint8_t *content, uint32_t content_len)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    const char *shared = UserManager::Instance()->GetShared(account);
    if (NULL == shared)
    {
        printf("ec_gen_register_mail_code : failed\n");
        return 0;
    }

    int outLen = (content_len / 16 + 1) * 16;
    int len = 0;
    uint8_t *out = (uint8_t *)malloc(outLen);
    aes_gcm_decrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    content, content_len,
                    out, &len);

    if (len <= 0)
    {
        printf("ec_gen_register_mail_code : decrypted failed\n");
        free(out);
        return 0;
    }

    uint32_t code = gen_random_code();
    UserManager::Instance()->PushUserMailMap(code, (const char *)out);
    free(out);
    return code;
}

uint32_t ec_register_mail(const char *account,
                          uint8_t *code_cipher, uint32_t cipher_code_len,
                          uint8_t *sealedStr, int sealedSize)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    const char *shared = UserManager::Instance()->GetShared(account);

    if (NULL == shared)
    {
        printf("ec_register_mail failed : account not exist\n");
        return SGX_ERROR_UNEXPECTED;
    }

    int outLen = (cipher_code_len / 16 + 1) * 16;
    int outhowmany = 0;
    uint8_t *out = (uint8_t *)malloc(outLen);
    aes_gcm_decrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    code_cipher, cipher_code_len,
                    out, &outhowmany);

    std::string sc(out, out + outhowmany);
    int code = atoi(sc.c_str());
    free(out);
    uint32_t sealed_size = 0;
    if (UserManager::Instance()->EmailIndexExisted(code))
    {
        const char *email = UserManager::Instance()->GetEmail(code);
        User user = UserManager::Instance()->GetUser(account);
        user.SetEmail(email);
        UserManager::Instance()->RemoveUserMailIndex(code);

        sgx_sealed_data_t *sealed_data = seal_data(reinterpret_cast<uint8_t *>(const_cast<char *>(email)), strlen(email), &sealed_size);
        sealedSize = sealed_size;
        memcpy(sealedStr, sealed_data, sealed_size);

        free(sealed_data);
    }
    else
    {
        printf("ec_register_mail failed : code not exist\n");
        return SGX_ERROR_UNEXPECTED;
    }

    return sealed_size;
}

sgx_status_t ec_register_password(const char *account,
                                  uint8_t *code_cipher, uint32_t cipher_code_len,
                                  uint8_t *sealedStr, int sealedSize)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);
    const char *shared = UserManager::Instance()->GetShared(account);

    if (NULL == shared)
    {
        printf("ec_register_password failed : account not exist\n");
        return SGX_ERROR_UNEXPECTED;
    }

    int outLen = (cipher_code_len / 16 + 1) * 16;
    int outhowmany = 0;
    uint8_t *out = (uint8_t *)malloc(outLen);
    aes_gcm_decrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    code_cipher, cipher_code_len,
                    out, &outhowmany);

    uint32_t sealed_size = 0;
    sgx_sealed_data_t *sealed_data = seal_data(out, outhowmany, &sealed_size);
    memcpy(sealedStr, sealed_data, sealed_size);

    free(out);
    free(sealed_data);

    return static_cast<sgx_status_t>(0);
}

uint32_t ec_register_gauth(const char *account, uint8_t *code_cipher, uint8_t *sealedStr)
{
    auto lock = KSSpinLock(&ks_op_spin_lock);

    const char *shared = UserManager::Instance()->GetShared(account);

    if (NULL == shared)
    {
        printf("ec_register_gauth failed : account not exist\n");
        return 0;
    }

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

    int outLen = (sizeof(s) / 16 + 1) * 16;
    int len = 0;
    uint8_t *out = (uint8_t *)malloc(outLen);
    aes_gcm_encrypt((const unsigned char *)shared, 256, IV, sizeof(IV),
                    (const unsigned char *)s, sizeof(s),
                    out, &len);
    memcpy(code_cipher, out, len);

    uint32_t sealed_size = 0;
    sgx_sealed_data_t *sealed_data = seal_data((uint8_t *)s, sizeof(s), &sealed_size);
    memcpy(sealedStr, sealed_data, sealed_size);

    free(out);
    free(sealed_data);

    return sealed_size;
}

sgx_status_t ec_verify_gauth_code(int gauth_code, char *secret, uint64_t tm)
{
    if (gauth_code <= 0)
    {
        printf("gauth_code can not be zero\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (strlen(secret) <= 0)
    {
        printf("secret is not avaliable\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (tm <= 0)
    {
        printf("tm is not avaliable %ld\n", tm);
        return SGX_ERROR_UNEXPECTED;
    }

    const unsigned long t = tm / 30;
    const int correct_code = generateCode(secret, t);
    printf("%d %d\n", gauth_code, correct_code);
    if (gauth_code != correct_code)
    {
        printf("code is not equal\n");
        return SGX_ERROR_UNEXPECTED;
    }

    return static_cast<sgx_status_t>(0);
}

// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t *p_message,
                                   size_t message_size,
                                   uint8_t *p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if (mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if (message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do
    {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if (SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if (SGX_SUCCESS != ret)
        {
            break;
        }
        if (0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    } while (0);

    return ret;
}

// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do
    {
        if (secret_size != 8)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret)
        {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         &g_secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)(p_gcm_mac));

        uint32_t i;
        bool secret_match = true;
        for (i = 0; i < secret_size; i++)
        {
            if (g_secret[i] != i)
            {
                secret_match = false;
            }
        }

        if (!secret_match)
        {
            ret = SGX_ERROR_UNEXPECTED;
        }

        // Once the server has the shared secret, it should be sealed to
        // persistent storage for future use. This will prevents having to
        // perform remote attestation until the secret goes stale. Once the
        // enclave is created again, the secret can be unsealed.
    } while (0);
    return ret;
}
