#include "UUser.h"
#include "KSSgx.h"
#include "Enclave_KS_u.h"
#include "ErrorSupport.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <unistd.h>

#include "AesGcmEncrypt.h"
#include "AesGcmDecrypt.h"

UUser::UUser()
{
}

UUser::~UUser()
{
}

bool UUser::init()
{
    if (!this->generate_key())
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

    char *hex = (char *)malloc(256);
    char *sharedStr = (char *)malloc(256);
    ret = ec_ks_exchange(eid, &retval, ec_pkey_hex, hex, sharedStr);
    free(sharedStr);

    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(hex);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(hex);
        return false;
    }

    enclave_hex.append(hex, strlen(hex));

    char s[256];
    memset(s, 0, 256);
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
    if (ret != SGX_SUCCESS)
    {
        printf("ec_auth call failed\n");
        return;
    }

    printf("UUser | auth_code %d\n", auth_code);
    if (auth_code > 0)
    {
        std::string ot = std::to_string(auth_code);
        int outlen = (ot.length() / 16 + 1) * 16;
        int outhowmany = 0;
        uint8_t *out = (uint8_t *)malloc(outlen);
        aes_gcm_encrypt((const unsigned char *)shared.c_str(),
                        256, IV, sizeof(IV), (const unsigned char *)ot.c_str(), ot.length(), out, &outhowmany);

        ret = ec_auth_confirm(eid, &retval, account.c_str(), out, outhowmany);
        free(out);
        if (ret != SGX_SUCCESS)
        {
            ret_error_support(ret);
            return;
        }
        else if (retval != SGX_SUCCESS)
        {
            ret_error_support(retval);
            return;
        }
    }
}

void UUser::RegisterMail()
{
    sgx_status_t ret;
    uint32_t mail_code = 0;

    sgx_enclave_id_t eid = KSSgx::Instance()->getEid();
    /*
    int outlen = (this->account.length()/16+1)*16;
    int outhowmany = 0;
    uint8_t* out = (uint8_t*)malloc(outlen);
    aes_gcm_encrypt((const unsigned char*)shared.c_str(),256,
            IV, sizeof(IV), (const unsigned char*)this->account.c_str(), this->account.length(),
            out, &outhowmany);
     */
    auto pAGE = AesGcmEncrypt((const unsigned char *)shared.c_str(), (const unsigned char *)this->account.c_str(), this->account.length());

    ret = ec_gen_register_mail_code(eid, &mail_code, this->account.c_str(), pAGE.data, pAGE.size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return;
    }

    if (mail_code <= 0)
    {
        printf("UUser | mail code is zero\n");
        return;
    }

    std::string codeStr = std::to_string(mail_code);
    auto pECode = AesGcmEncrypt((const unsigned char *)shared.c_str(), (const unsigned char *)codeStr.c_str(), codeStr.length());

    uint32_t sealed_size = 0;
    ret = ec_calc_sealed_size(eid, &sealed_size, this->account.length());
    if (ret != SGX_SUCCESS)
    {
        printf("UUser | ec_calculate sealed size failed\n");
        return;
    }

    uint32_t seal_data_size = 0;
    uint8_t *sealedData = (uint8_t *)malloc(sealed_size);
    ret = ec_register_mail(eid, &seal_data_size, this->account.c_str(), pECode.data, pECode.size, sealedData, sealed_size);
    if (ret != SGX_SUCCESS)
    {
        printf("UUser | ec_register_mail failed\n");
        free(sealedData);
        return;
    }

    free(sealedData);
}

void UUser::RegisterGauth()
{
    sgx_status_t ret;
    uint32_t retval = 0;
    uint8_t *secret_cipher = (uint8_t *)malloc(256);
    uint8_t *sealedStr = (uint8_t *)malloc(1024);

    sgx_enclave_id_t eid = KSSgx::Instance()->getEid();
    ret = ec_register_gauth(eid, &retval, this->account.c_str(), secret_cipher, sealedStr);
    if (ret != SGX_SUCCESS)
    {
        free(secret_cipher);
        free(sealedStr);
        return;
    }

    auto pSecretDecrypt = AesGcmDecrypt((const unsigned char *)this->shared.c_str(), secret_cipher, 256);

    printf("%s\n", pSecretDecrypt.data);

    free(secret_cipher);
    free(sealedStr);
}

bool UUser::generate_key()
{
    ec_pkey = EC_KEY_new();
    if (ec_pkey == NULL)
    {
        printf("%s\n", "EC_KEY_new err!");
        return false;
    }
    int crv_len = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve *curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
    EC_get_builtin_curves(curves, crv_len);
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL)
    {
        printf("%s\n", "Group new failed");
        return false;
    }

    unsigned int ret = EC_KEY_set_group(ec_pkey, group);
    if (ret != 1)
    {
        printf("%s\n", "EC_KEY_Set_group failed");
        return false;
    }

    ret = EC_KEY_generate_key(ec_pkey);
    if (ret != 1)
    {
        printf("%s\n", "EC_KEY_generate_key failed");
        return false;
    }

    ret = EC_KEY_check_key(ec_pkey);
    if (ret != 1)
    {
        printf("%s\n", "check key failed");
        return false;
    }

    free(curves);

    return true;
}

void UUser::RemoteAttestation()
{
    
    int ret = -1;

    sgx_enclave_id_t enclave_id = KSSgx::Instance()->getEid();
    int enclave_lost_retry_time = 2;

    FILE *OUTPUT = stdout;

    uint32_t extended_epid_group_id = 0;
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if (SGX_SUCCESS != ret)
    {
        ret = -1;
        printf("\nError, call sgx_get_extended_epid_group_id failed [%s]", __FUNCTION__);
        return;
    }
    printf("\ncall sgx_get_extended_epid_group_id success");

    p_msg0_full = (ra_samp_request_header_t *)
        malloc(sizeof(ra_samp_request_header_t) + sizeof(uint32_t));
    if (NULL == p_msg0_full)
    {
        raCleanup();
        return;
    }
    p_msg0_full->type = TYPE_RA_MSG0;
    p_msg0_full->size = sizeof(uint32_t);
    *(uint32_t *)((uint8_t *)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
    {
        printf("\nMSG0 body generated - \n");
        PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);
    }
    fprintf(OUTPUT, "\nSending msg0 to remote attestation service provider.\n");

    ret = ra_network_send_receive("http://SampleServiceProvider.intle.com/", 
                                                            p_msg0_full, 
                                                            &p_msg0_resp_full);
    if (ret != 0)
    {
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed [%s].", __FUNCTION__);
        raCleanup();
        return;
    }
    fprintf(OUTPUT, "\nSent MSG0 to remote attestation service.\n");

    ret = sgx_select_att_key_id(p_msg0_resp_full->body, p_msg0_resp_full->size, &selected_key_id);
    if (SGX_SUCCESS != ret)
    {
        fprintf(OUTPUT, "\ninfo, call sgx_select_att_key_id fail, current platform configuration doesn't support this attestation KEY ID. [%s]", __FUNCTION__);
        raCleanup();
        return;
    }
    fprintf(OUTPUT, "\nCall sgx_select_att_key_id success");

    do
    {
        ret = enclave_init_ra(enclave_id, &status, false, &context);
    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if (SGX_SUCCESS != ret || status)
    {
        ret_error_support((sgx_status_t)ret);
        ret = -1;
        fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
                __FUNCTION__);
        raCleanup();
        return;
    }
    fprintf(OUTPUT, "\nCall enclave_init_ra success.");

    // isv application call uke sgx_ra_get_msg1
    p_msg1_full = (ra_samp_request_header_t *)
        malloc(sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t));
    if (NULL == p_msg1_full)
    {
        raCleanup();
        return;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);
    int busy_retry_time = 2;
    do
    {
        ret = sgx_ra_get_msg1_ex(&selected_key_id, context, 
                enclave_id, sgx_ra_get_ga, 
                (sgx_ra_msg1_t *)((uint8_t *)p_msg1_full + sizeof(ra_samp_request_header_t)));
        // TODO need to fix
        sleep(1); // Wait 3s between retries
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if (SGX_SUCCESS != ret)
    {
        ret_error_support((sgx_status_t)ret);
        ret = -1;
        fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1_ex fail [%s].",
                __FUNCTION__);
        raCleanup();
        return;
    }
    else
    {
        fprintf(OUTPUT, "\nCall sgx_ra_get_msg1_ex success.\n");

        fprintf(OUTPUT, "\nMSG1 body generated -\n");

        PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
    }
    fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider. Expecting msg2 back.\n");
    ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/", p_msg1_full, &p_msg2_full);

    if (ret != 0 || !p_msg2_full)
    {
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
                        "[%s].",
                __FUNCTION__);
    }
    else
    {
        if (TYPE_RA_MSG2 != p_msg2_full->type)
        {
            fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
                            "[%s].",
                    __FUNCTION__);
            raCleanup();
            return;
        }
    }
    fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
                    "provider. Received the following MSG2:\n");
    PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                     (uint32_t)sizeof(ra_samp_response_header_t) + p_msg2_full->size);

    fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
    PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

    sgx_ra_msg2_t *p_msg2_body = (sgx_ra_msg2_t *)((uint8_t *)p_msg2_full + sizeof(ra_samp_response_header_t));
    uint32_t msg3_size = 1452;
    p_msg3 = (sgx_ra_msg3_t *)malloc(msg3_size);
    busy_retry_time = 2;
    do
    {
        ret = sgx_ra_proc_msg2_ex(&selected_key_id,
                                  context,
                                  enclave_id,
                                  sgx_ra_proc_msg2_trusted,
                                  sgx_ra_get_msg3_trusted,
                                  p_msg2_body,
                                  p_msg2_full->size,
                                  &p_msg3,
                                  &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if (!p_msg3)
    {
        fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2_ex fail."
                        "p_msg3=0x%p [%s].",
                p_msg3, __FUNCTION__);
        raCleanup();
        return;
    }

    if (SGX_SUCCESS != (sgx_status_t)ret)
    {
        ret_error_support((sgx_status_t)ret);
        fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2_ex fail."
                        "ret = 0x%08x[%s]",
                ret, __FUNCTION__);
        raCleanup();
        return;
    }
    else
    {
        fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2_ex success.\n");
        fprintf(OUTPUT, "\nMSG3-\n");
    }

    PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    p_msg3_full = (ra_samp_request_header_t *)malloc(sizeof(ra_samp_request_header_t) + msg3_size);
    if (NULL == p_msg3_full)
    {
        raCleanup();
        return;
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;
    if (memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
    {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]", __FUNCTION__);
        raCleanup();
        return;
    }

    ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/", p_msg3_full, &p_att_result_msg_full);
    if (ret || !p_att_result_msg_full)
    {
        ret = -1;
        fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
        raCleanup();
        return;
    }

        sample_ra_att_result_msg_t *p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t *)p_att_result_msg_full + sizeof(ra_samp_response_header_t));
        if (TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                            "received was NOT of type att_msg_result. Type = "
                            "%d. [%s].",
                    p_att_result_msg_full->type,
                    __FUNCTION__);
                raCleanup();
                return;
        }
        else
        {
            fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation"
                            "result message back\n");
        }
        fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED -");
        PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body, p_att_result_msg_full->size);

        ret = verify_att_result_mac(enclave_id, &status, context,
                                    (uint8_t *)&p_att_result_msg_body->platform_info_blob,
                                    sizeof(ias_platform_info_blob_t),
                                    (uint8_t *)&p_att_result_msg_body->mac,
                                    sizeof(sgx_mac_t));
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status))
    {
        ret = -1;
        fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result"
                        "message MK based cmac failed in [%s]",
                __FUNCTION__);
            raCleanup();
            return;
    }

    {
        bool attestation_passed = true;
        if (0 != p_att_result_msg_full->status[0] || 0 != p_att_result_msg_full->status[1])
        {
            fprintf(OUTPUT, "\nError, attestation result message MK based cmac"
                            "failed in [%s].",
                    __FUNCTION__);
            attestation_passed = false;
        }

        if (attestation_passed)
        {
            ret = put_secret_data(enclave_id,
                                  &status,
                                  context,
                                  p_att_result_msg_body->secret.payload,
                                  p_att_result_msg_body->secret.payload_size,
                                  p_att_result_msg_body->secret.payload_tag);
            if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status))
            {
                fprintf(OUTPUT, "\nError, attestation result message secret "
                                "using SK based AESGCM failed in [%s]. ret = "
                                "0x%0x. status = 0x%0x",
                        __FUNCTION__, ret,
                        status);
                raCleanup();
                return;
            }
        }
        fprintf(OUTPUT, "\nSecret successfully received from server.");
        fprintf(OUTPUT, "\nRemote attestation success!");
    }
}

void UUser::raCleanup()
{
    sgx_enclave_id_t enclave_id = KSSgx::Instance()->getEid();
  if (INT_MAX != context)
    {
        int ret_save = - 1;
        int ret = enclave_ra_close(enclave_id, &status, context);
        if (SGX_SUCCESS != ret || status)
        {
            ret = -1;
            printf("\nError, call enclave_ra_close failed [%s]", __FUNCTION__);
        }
        else
        {
            ret = ret_save;
        }
        printf("\nCall enclave_ra_close success.\n");
    }
    // sgx_destory_enclave(enclave_id);
    ra_free_network_response_buffer(p_msg0_resp_full);
    p_msg0_resp_full = NULL;
    ra_free_network_response_buffer(p_msg2_full);
    p_msg2_full = NULL;
    ra_free_network_response_buffer(p_att_result_msg_full);
    p_att_result_msg_full = NULL;

    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);
}
