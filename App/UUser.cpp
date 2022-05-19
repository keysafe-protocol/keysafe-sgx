#include "UUser.h"
#include "KSSgx.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"
#include "global.h"
#include <vector>
#include <sstream>
#include <iomanip>

UUser::UUser()
{

}

UUser::~UUser()
{
}

bool UUser::init()
{
    if(!this->generate_key())
    {
        printf("%s, generate_key failed", __FILE__);
        return false;
    }

    const EC_POINT *point = EC_KEY_get0_public_key(ec_pkey);
    char *ec_pkey_hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    user_hex.clear();
    user_hex.append(ec_pkey_hex);

    sgx_status_t ret, retval;
    sgx_enclave_id_t eid = KSSgx::Instance()->getEid();

    char* hex = (char*)malloc(256);
    char* sharedStr = (char*)malloc(256);
    ret = ec_ks_exchange(eid, &retval, ec_pkey_hex, hex, sharedStr);
    free(sharedStr);

    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(hex);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(hex);
        return  false;
    }

    enclave_hex.append(hex, strlen(hex));

    char s[256];
    memset(s,0, 256);
    EC_POINT *uPoint = EC_POINT_hex2point(group, enclave_hex.c_str(), NULL, NULL);
    int len = ECDH_compute_key(s, 256, uPoint, ec_pkey, NULL);
    shared.append(s, len);

    free(hex);

    return true;
}

void UUser::auth()
{
    uint32_t auth_code = 0;
    sgx_status_t ret, retval;
    sgx_enclave_id_t eid = KSSgx::Instance()->getEid();

    ret = ec_auth(eid, &auth_code, account.c_str(), user_hex.c_str());
    if(ret != SGX_SUCCESS)
    {
        printf("ec_auth call failed\n");
        return;
    }

    printf("auth_code %d\n", auth_code);
    if(auth_code > 0)
    {
        std::string ot = std::to_string(auth_code);
        int outlen = (ot.length()/16+1)*16;
        int outhowmany = 0;
        uint8_t* out = (uint8_t*)malloc(outlen);
        aes_gcm_encrypt((const unsigned char*)shared.c_str(),
                256, IV, sizeof(IV), (const unsigned char*)ot.c_str(), ot.length(), out, &outhowmany);

        ret = ec_auth_confirm(eid, &retval, account.c_str(), out, outhowmany);
        free(out);
        if(ret != SGX_SUCCESS)
        {
            ret_error_support(ret);
            return;
        }
        else if(retval != SGX_SUCCESS)
        {
            ret_error_support(retval);
            return;
        }
    }
}



bool UUser::generate_key()
{
    ec_pkey= EC_KEY_new();
    if(ec_pkey == NULL)
    {
        printf("%s\n","EC_KEY_new err!");
        return false;
    }
    int crv_len = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve *curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve)*crv_len);
    EC_get_builtin_curves(curves, crv_len);
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(group == NULL)
    {
        printf("%s\n", "Group new failed");
        return false;
    }

    unsigned int ret = EC_KEY_set_group(ec_pkey, group);
    if(ret != 1)
    {
        printf("%s\n","EC_KEY_Set_group failed");
        return false;
    }

    ret = EC_KEY_generate_key(ec_pkey);
    if(ret!=1)
    {
        printf("%s\n", "EC_KEY_generate_key failed");
        return false;
    }

    ret = EC_KEY_check_key(ec_pkey);
    if(ret !=1)
    {
        printf("%s\n","check key failed");
        return false;
    }

    free(curves);

    return true;
}


