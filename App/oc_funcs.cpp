#include "oc_funcs.h"
#include "KSSgx.h"

void uprint(const char* str)
{
    printf("%s", str);
}

void oc_deliver_public_key(const char *str)
{
    KSSgx::Instance()->InitPubKey(str);
}


