#include "ks_enclave_util.h"
#include "Enclave_KS_t.h"

void printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    oc_print(buf);
}
