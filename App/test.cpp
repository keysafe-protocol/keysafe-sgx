#include <string>
#include <vector>

#include "test.h"
#include "global.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"


char* test_out_public_key(sgx_enclave_id_t eid_t, char* userpkHex)
{
    sgx_status_t ret, ret_val;
    char* str = (char*)malloc(256);
    char* sharedStr = (char*)malloc(256);
    ret = ec_ks_exchange(eid_t,&ret_val, userpkHex, str, sharedStr);
    printf("%s %d %d\n", str, ret, ret_val);
    free(sharedStr);
    //ret = ec_rand_num(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return NULL;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return NULL;
    }

    return str;

}


void test_gen_rand_num(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    //ret = ec_rand_num(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_gen_key(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    ret = ec_gen_key(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}


void test_encrypt(sgx_enclave_id_t eid_t, const char* str)
{
    sgx_status_t ret, ret_val;
    ret = ec_rsa_encrypt(eid_t, &ret_val, str);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_rsa_decrypt(sgx_enclave_id_t eid_t)
{
    std::string strSource = "source text,hello world";
    sgx_status_t ret, ret_val;
    ret = ec_rsa_decrypt(eid_t, &ret_val, (const char*)strSource.c_str());
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_aes_decrypt(sgx_enclave_id_t eid_t, char* str)
{
    sgx_status_t ret, ret_val;
    printf("To decrypt str\n", str);
    char shared[]  = "968426f0380ab40d5740893742130731e86c163a33304ac7824d388e52f6eab3";
    unsigned char ciphertext[] = {114, 131, 171, 231, 32, 156, 68, 233, 109, 16, 209, 21, 38, 181, 218, 48, 84, 54, 54, 82, 90, 136, 40, 102, 239, 193, 183, 15, 187, 165, 25, 217, 85, 9, 13};
    ret = ec_aes_gcm_decrypt(eid_t, &ret_val, shared, (char*)ciphertext);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

uint8_t* test_seal_and_save_data(sgx_enclave_id_t eid_t, uint32_t* sz)
{
    uint8_t array[] ={
        6, 212, 209, 242, 197, 228, 236, 40, 71, 76, 218, 140, 20, 230, 148, 96, 28, 187, 164, 50, 171, 21, 103, 166, 47, 86, 244, 78, 156, 121, 165, 255, 211, 30, 156, 75, 47, 17, 133, 75, 39, 85, 114, 41, 255, 199, 73, 128, 182, 120, 161, 219, 253, 33, 57, 123, 131, 191, 144, 194, 47, 186, 138, 168, 84, 227, 91, 110, 197, 145, 58, 85, 222, 153, 215, 178, 193, 99, 106, 107, 216, 53, 193, 52, 213, 221, 173, 58, 27, 34, 196, 23, 57, 51, 245, 210, 133, 34, 12, 155, 224, 18, 4, 49, 94, 155, 163, 204, 17, 15, 85, 123, 39, 226, 146, 242, 145, 28, 253, 122, 209, 216, 6, 132, 78, 43, 49, 5, 180, 249, 166, 203, 159, 121, 13, 126, 228, 125, 73, 46, 12, 91, 145, 129, 67, 2, 193, 205, 44, 168, 6, 178, 135, 231, 193, 201, 38, 149, 3, 18, 200, 153, 245, 76, 54, 117, 140, 9, 107, 10, 145, 76, 0, 125, 2, 18, 77, 141, 131, 78, 144, 206, 44, 187, 13, 84, 37, 251, 115, 55, 97, 178, 11, 167, 223, 41, 14, 2, 50, 2, 232, 17, 231, 74, 244, 97, 123, 23, 178, 80, 46, 215, 99, 212, 235, 28, 78, 104, 211, 19, 202, 16, 226, 37, 14, 180, 17, 132, 180, 106, 67, 184, 25, 195, 132, 84, 192, 222, 51, 105, 62, 157, 46, 12, 143, 119, 182, 174, 7, 73, 251, 154, 249, 88, 181, 212, 251, 25, 189, 60, 252, 218, 97, 173, 17, 155, 36, 94, 114, 202, 38, 205, 142, 192, 251, 148, 178, 254, 39, 241, 46, 143, 8, 78, 200, 176, 92, 255, 253, 233, 221, 149, 72, 110, 177, 149, 22, 43, 53, 162, 113, 51, 129, 111, 88, 22, 39, 144, 240, 235, 54, 38, 62, 140, 46, 138, 153, 90, 101, 60, 112, 0, 107, 247, 37, 73, 93, 222, 107, 95, 70, 176, 111, 30, 155, 91, 243, 95, 188, 52, 249, 73, 206, 152, 104, 87, 197, 142, 50, 51, 96, 103, 35, 81, 245, 111, 213, 223, 112, 190, 110, 232, 137, 149, 47, 197, 67, 41, 160, 157, 96, 100, 57, 188, 177, 48, 40, 178, 70, 83, 87, 22, 118, 219, 205, 8, 216, 0, 253, 187, 6, 197, 210, 107, 205, 94, 139, 24, 120, 191, 181, 22, 59, 84, 70, 181, 47, 106, 233, 168, 44, 37, 43, 143, 74, 110, 4, 251, 45, 77, 225, 46, 28, 136, 224, 3, 64, 122, 179, 191, 83, 46, 108, 131, 207, 33, 149, 112, 159, 159, 8, 237, 186, 163, 254, 42, 226, 197, 255, 118, 203, 197, 156, 20, 93, 158, 75, 128, 187, 63, 14, 32, 66, 7, 68, 251, 125, 135, 143, 241, 121, 118, 92, 136, 174, 91, 159, 81, 169, 211, 41, 124, 81, 30, 228, 75, 230, 193, 39, 45, 242, 100, 33, 23, 183, 180, 2, 126, 106, 154, 2, 163, 143, 204, 13, 224, 64, 18, 177, 104, 170, 220, 14, 188, 152, 68, 144, 20, 0, 130, 165, 172, 116, 138, 187, 133, 220, 131, 19, 180, 48, 155, 128, 226, 45, 28, 14, 149, 105, 91, 183, 252, 208, 11, 123, 55, 133, 69, 13, 150, 153, 23, 40, 8, 145, 19, 15, 56, 126, 92, 69, 251, 211, 45, 245, 5, 214, 206, 132, 28, 193, 13, 222, 251, 109, 207, 140, 23, 61, 79, 189, 94, 211, 33, 215, 12, 76, 241, 45, 42, 207, 132, 154, 81, 189, 117, 131, 32, 228, 147, 124, 210, 48, 229, 200, 39, 172, 211, 227, 158, 161, 116, 143, 2, 98, 153, 39, 158, 19, 240, 194, 238, 162, 140, 126, 231, 140, 210, 89, 63, 132, 41, 32, 250, 179, 80, 151, 87, 121, 241, 43, 78, 185, 224, 101, 179, 146, 70, 53, 69, 134, 253, 142, 84, 230, 171, 155, 163, 27, 69, 35, 24, 139, 179, 11, 155, 191, 152, 99, 39, 94, 219, 215, 3, 221, 53, 110, 156, 57, 31, 169, 229, 99, 231, 156, 121, 8, 111, 177, 3, 181, 158, 40, 187, 56, 46, 195, 36, 126, 124, 221, 218, 122, 142, 151, 81, 216, 73, 196, 110, 175, 234, 89, 132, 182, 36, 227, 68, 19, 119, 134, 153, 12, 226, 198, 118, 98, 125, 73, 60, 252, 59, 67, 246, 92, 140, 146, 145, 10, 164, 26, 61, 230, 113, 109, 42, 64, 148, 148, 235, 1, 228, 41, 157, 128, 72, 117, 187, 147, 101, 25, 113, 236, 236, 127, 142, 104, 70, 118, 101, 248, 236, 244, 161, 250, 95, 93, 180, 188, 105, 199, 39, 192, 217, 215, 72, 253, 175, 146, 198, 206, 15, 6, 159, 76, 213, 211, 52, 149, 209, 132, 1, 205, 78, 42, 230, 13, 132, 121, 13, 12, 91, 99, 67, 150, 76, 22, 29, 9, 234, 136, 195, 156, 204, 99, 194, 195, 126, 122, 176, 83, 67, 25, 25, 208, 44, 229, 76, 3, 2, 234, 228, 204, 57, 25, 192, 221, 161, 170, 255, 62, 132, 121, 182, 67, 236, 3, 70, 200, 246, 255, 194, 205, 194, 163, 214, 46, 2, 86, 79, 124, 32, 241, 222, 53, 27, 45, 195, 70, 101, 79, 227, 219, 192, 47, 6, 14, 61, 136, 151, 86, 6, 110, 57, 107, 37, 168, 208, 156, 174, 70, 64, 206, 80, 161, 88, 202, 168, 43, 193, 171, 198, 244, 205, 183, 26, 92, 9, 63, 210, 8, 191, 32, 212, 187, 152, 72, 142, 53, 153, 198, 177, 56, 29, 255, 214, 129, 213, 164, 155, 204, 103, 87, 130, 237, 4, 54, 180, 194, 17, 179, 86, 112, 138, 40, 69, 42, 152, 36, 227, 217, 152, 233, 200, 15, 163, 54, 215, 148, 117, 214, 25, 164, 40, 118, 43, 221, 74, 62, 232, 3, 220, 143, 139, 179, 131, 100, 97, 235, 63, 189, 183, 35, 80, 64, 116, 222, 43, 150, 243, 19, 70, 224, 53, 100, 192, 127, 3, 230, 191, 25, 9, 109, 70, 179, 8, 173, 85, 175, 134, 166, 4, 100, 174, 177, 24, 136, 160, 177, 55, 211, 106, 119, 222, 107, 230, 3, 103, 240, 149, 99, 121, 237, 68, 56, 36, 140, 250, 185, 11, 41, 171, 16, 168, 41, 61, 175, 127, 66, 235, 122, 3, 68, 51, 25, 237, 24, 160, 197, 10, 186, 0, 241, 45, 124, 21, 112, 199, 218, 197, 215, 57, 0, 245, 25, 135, 14, 120, 175, 204, 3, 195, 125, 51, 127, 3, 150, 113, 63, 162, 154, 204, 62, 103
    };

    printf("array size %d\n", sizeof(array));
    sgx_status_t ret, ret_val;
    std::string str2="801d5de56dfde3522c93c4f371e717f4e9946624dc66083b7554839c8532711cd7fc6b0a53fee3e427c85c5ae06971c6cf423559464f3cf5149818dac295a1c6bb019f54fb07bb79333a883fd6e0accb55a459ae6258bdc1ba136292d0d517b3bb323cdc1f79ad0ca3bbdd4b56c6658bc3c4191235a0a45785cca07975feae13f5636dbc68e11c46025b7c3bda74dbe14cdef82a7b3bc1836f0f1478b784ea813aacfa76c65f7f9aef56075646e2c137ea97856925b8662efe25eb59bf087c44017c05c13b67468690a6f0c33964c1f96366b342ac8ec6acb9bc6d1fcb0606bfc694c5d313a085b17b9b1dcb5e1cd0f063389526325a3e47712764756fe48925591aa97815b2a9ba9869dd2c724060aa32053a0f352733bdde06dccb3ff39c5d3cef1375eb1a55eade6cc6931f7f96bb949970d9054b7ead4e672466d21fdb1cfc6dbef6d7b04fe34d37844e43cdd95a3849efd274a6e2cab236dca078da2aaf81fb8d1f36930d2032479cae52b643e9245ecb546e85184b9190382cc71dc6a044eb3e47159b50470927cb90dedebce6c792f565040b83b8d0ddb44dbacc7595c101237ce66e40013678a96dd9753c0a8bf7ccbdb6afd1376c29e6f179a9d5fade43694be91350eb050c9011364017328a57ba9b282020c62948722b8ae5d4ad9df81c4bbef4fe6a099780881c0f6757e0ede12a80a43519a8ddd82e25c6da0620225fe4733fec3d4e93554ac7fa44d86daf881c672a8a51327e3f284127a056128";
    uint32_t sealedSize = 0;
    ec_calc_sealed_size(eid_t, &sealedSize, str2.length());
    *sz = sealedSize;
    printf("calc sealed size %d\n", sealedSize);
    uint8_t * str = (uint8_t*)malloc(sealedSize);
    ret = ec_ks_seal(eid_t, &ret_val,(const char*)array, sizeof(array),
                                str, sealedSize);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(str);
        return NULL;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        free(str);
        return NULL;
    }
    printf("sealed %s\n", str);
    return str;
}


void test_read_unseal_data(sgx_enclave_id_t eid_unseal, uint8_t* sealedBlob, uint32_t data_size)
{
    sgx_status_t ret, ret_val;
    uint32_t randVal =0;
    std::string str = "hello";
    printf("test 2\n");
    ret = ec_ks_unseal(eid_unseal, &randVal, str.c_str(), sealedBlob, data_size);
    printf("%d", randVal);
    printf("\n");
    if(ret != SGX_SUCCESS)
    {
        printf("test 1\n");
        ret_error_support(ret);
        return;
    }
    char* unsealStr = (char*)malloc(8192);
    uint32_t len = 0;
    ret = ec_prove_me(eid_unseal, &len, (uint8_t*)&randVal, 10, unsealStr);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(unsealStr);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        free(unsealStr);
        return;
    }
    printf("prove me %s\n", unsealStr);
    free(unsealStr);
}

void test_get_public_key(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    ret = ec_deliver_public_key(eid_t, &ret_val);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}

void test_gen_gauth_secret(sgx_enclave_id_t eid_t)
{
    sgx_status_t ret, ret_val;
    uint32_t sealed_size = 0;
    uint32_t slen = 0;
    int sealed_len =0;
    ec_calc_sealed_size(eid_t, &sealed_size, 210);
    printf("calc sealed size %d\n", sealed_size);
    uint8_t* secret = (uint8_t*)malloc(sealed_size);
    uint8_t* encrypted_secret = (uint8_t*)malloc(256);
    ret = ec_gen_gauth_secret(eid_t, &ret_val, secret, (int)sealed_size, encrypted_secret);
    free(secret);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }
    else if(ret_val != SGX_SUCCESS)
    {
        ret_error_support(ret_val);
        return;
    }
}
