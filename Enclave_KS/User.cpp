#include "User.h"

void User::Exchange(const char* userpkeyHex, const char* sharedStr)
{
    m_userpkeyHex.append(userpkeyHex);
    m_shared.append(sharedStr);
}
