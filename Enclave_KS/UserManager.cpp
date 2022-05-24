#include "UserManager.h"
#include "Enclave_KS_t.h"
#include "ks_enclave_util.h"

UserManager* UserManager::m_instance = NULL;

void UserManager::PushExchangeUser(const char* userpkeyhex, User user)
{
    std::string hex;
    hex.append(userpkeyhex, strlen(userpkeyhex));
    m_userExchangedMap[hex] = user;
}

bool UserManager::PushAvaliableUser(const char* account, const char* userpkeyhex)
{
    std::string hex;
    hex.append(userpkeyhex);

    auto it = m_userExchangedMap.find(hex);
    if(it == m_userExchangedMap.end())
    {
        printf("use hex not exist\n");
        return false;
    }


    std::string strAccount;
    strAccount.append(account);

    User user = it->second;
    user.SetAccount(account);

    m_userAvaliableMap[strAccount] = hex;
    return true;
}

bool UserManager::ExchangeUserExisted(const char* userpkeyhex)
{
    std::string hex;
    hex.append(userpkeyhex);

    auto iter = m_userExchangedMap.find(hex);
    return iter != m_userExchangedMap.end() ? true : false;
}

bool UserManager::AvaliableUserExisted(const char* account)
{
    std::string k;
    k.append(account);

    auto iter = m_userAvaliableMap.find(k);
    return iter != m_userAvaliableMap.end()? true :false;
}

void UserManager::PushUserIndexMap(int index, std::string& strUserPpkeyhex)
{
    m_userIndexMap[index] = strUserPpkeyhex;
    for(auto var : m_userIndexMap)
    {
        printf("before %d ===> %s\n", var.first, var.second.c_str());
    }
}

bool UserManager::UserIndexExisted(int code)
{
    for(auto var : m_userIndexMap)
    {
        printf("after %d ===> %s\n", var.first, var.second.c_str());
        if(var.first == code)
        {
            return true;
        }
    }
    return false;

    /*
    std::map<int, std::string>::iterator iter = m_userIndexMap.find(code);
    return (iter != m_userIndexMap.end()) ? true: false;
    */
}

const char* UserManager::GetShared(const char* account)
{
    std::string k;
    k.append(account);

    auto it = m_userAvaliableMap.find(k);
    if(it == m_userAvaliableMap.end())
        return NULL;

    std::string hex = it->second;
    std::map<std::string, User>::iterator ait = m_userExchangedMap.find(hex);
    if(ait == m_userExchangedMap.end())
        return "";

    User &user = ait->second;
    return user.GetShared().c_str();
}

void UserManager::RemoveExchangeUser(const char* userpkeyhex)
{
    std::string hex;
    hex.append(userpkeyhex);
    m_userExchangedMap.erase(hex);
}

void UserManager::RemoveAvaliableUser(const char* account)
{
    std::string k;
    k.append(account);
    m_userAvaliableMap.erase(k);
}

void UserManager::RemoveUserIndex(int code)
{
    printf("remove user index %d\n", code);
    m_userIndexMap.erase(code);
}

void UserManager::PushUserMailMap(int code, const char* mail)
{
    std::string k;
    k.append(mail);
    m_userMailMap[code] = mail;
}

bool UserManager::EmailIndexExisted(int code)
{
    auto it = m_userMailMap.find(code);
    return (it != m_userMailMap.end()) ? true:false;
}

void UserManager::RemoveUserMailIndex(int code)
{
    m_userMailMap.erase(code);
}

const char* UserManager::GetEmail(int code)
{
    auto it = m_userMailMap.find(code);
    if(it == m_userMailMap.end())
        return NULL;

    std::string email = it->second;
    return email.c_str();
}

User& UserManager::GetUser(const char* account)
{
    std::string k;
    k.append(account);
    auto it = m_userAvaliableMap.find(k);
    std::string hex = it->second;

    auto uit = m_userExchangedMap.find(hex);
    return uit->second;
}


