#include "Enclave_KS_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

char encrypt_data[BUFSIZ] = "Data to encrypt";
char add_mac_text[BUFSIZ] = "add mac text";

sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));

    if(seal_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    if(seal_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* temp_sealed_buff = (uint8_t*)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
}
