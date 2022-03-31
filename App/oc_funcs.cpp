#include "oc_funcs.h"
#include <iostream>
#include <string>
//#include "KSSgx.h"

void oc_print(const char* str)
{
    printf("%s", str);
}

/*
void oc_deliver_public_key(const char *str)
{
    KSSgx::Instance()->InitPubKey(str);
}

void oc_encrypted_string(const char* str)
{
    printf("oc encrypted : %s\n", str);
}

void oc_deliver_sealed_string(const char* str)
{
    printf("%s\n", str);
}

void oc_deliver_unseal_string(const char* str)
{
    printf("%s\n", str);
}
*/
