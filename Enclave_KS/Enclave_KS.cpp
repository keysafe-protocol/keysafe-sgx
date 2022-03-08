#include <map>
#include <string>

#include "ks_enclave_ssl_funcs.h"
#include "ks_enclave_util.h"
#include "Enclave_KS_t.h"
#include "tSgxSSL_api.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#define ADD_ENTROPY_SIZE 32

std::map<std::string, std::string> client_pubkey_map;

EVP_PKEY *evp_pkey = NULL;
RSA *keypair = NULL;

/*
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    oc_print(buf);
}
*/

void rsa_key_gen()
{
	BIGNUM *bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return;
	}

	keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return;
	}
	ret = RSA_generate_key_ex(keypair, 3027, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return;
	}

	evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(evp_pkey, keypair);

	// public key - string
    /*
	int len = i2d_PublicKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);
    std::string strPublicKey;
    strPublicKey.append(reinterpret_cast<const char*>(buf));
    oc_deliver_public_key(strPublicKey.c_str());

    char * pem = (char*)malloc(len+1);
    FormatPubToPem(keypair, pem);
    free(pem);

	// prnint public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

    printf("test 1");
	// private key - string
	len = i2d_PrivateKey(evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
    */

	BN_free(bn);

    /*
	EVP_PKEY_free(evp_pkey);

	if (evp_pkey->pkey.ptr != NULL) {
	  RSA_free(keypair);
	}
    */
}


char encrypt_data[BUFSIZ] = "Data to encrypt";
char aad_mac_text[BUFSIZ] = "aad mac text";

sgx_status_t ec_gen_key()
{
    rsa_key_gen();
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_deliver_public_key()
{
    std::string base64;
    FormatPubToPem(keypair, base64);
    oc_deliver_public_key(base64.c_str());
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_rsa_encrypt(const char* from)
{
    char* out = (char*)encrypt(evp_pkey, from);
    std::string outStr;
    outStr.append(out);
    free(out);
    oc_encrypted_string(outStr.c_str());
    return static_cast<sgx_status_t>(0);
}

uint32_t ec_get_sealed_data_size()
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
}

sgx_status_t ec_ks_exchange_pair_key(const char* str)
{
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_ks_seal(const char *str)
{
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_ks_unseal(const char* str)
{
    return static_cast<sgx_status_t>(0);
}

sgx_status_t ec_seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));

    if(sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    if(sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* temp_sealed_buff = (uint8_t*)malloc(sealed_data_size);
    if(temp_sealed_buff == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    sgx_status_t err = sgx_seal_data((uint32_t)strlen(aad_mac_text),
                                        (const uint8_t*)aad_mac_text,
                                        (uint32_t)strlen(encrypt_data),
                                        (uint8_t*)encrypt_data,
                                        sealed_data_size,
                                        (sgx_sealed_data_t*)temp_sealed_buff);
    if(err == SGX_SUCCESS)
    {
        memcpy(sealed_blob, temp_sealed_buff, sealed_data_size);
    }

    free(temp_sealed_buff);
    return err;
}

sgx_status_t ec_unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t*)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_blob);

    if(mac_text_len==UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text = (uint8_t*)malloc(mac_text_len);
    if(de_mac_text == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *decrypt_data = (uint8_t*)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t*)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
    if(ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    if(memcmp(de_mac_text, aad_mac_text, strlen(aad_mac_text)) || memcmp(decrypt_data, encrypt_data, strlen(encrypt_data)))
    {
        ret = SGX_ERROR_UNEXPECTED;
    }

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

sgx_status_t ec_rsa_decrypt(const char *str)
{
    std::string source(str);
    size_t outlen = source.length() + 1;
    decrypt(evp_pkey, (unsigned char*)source.c_str(), outlen);

    return static_cast<sgx_status_t>(0);
}
