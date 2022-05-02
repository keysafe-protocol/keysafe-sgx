#include "User.h"
#include <cstring>

void User::Exchange(const char* userpkeyHex, const char* sharedStr)
{
    m_userpkeyHex.append(userpkeyHex, strlen(userpkeyHex));
    m_shared.append(sharedStr, strlen(sharedStr));
}
