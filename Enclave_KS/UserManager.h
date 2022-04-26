#ifndef __ENCLAVE_KS_USER_MANAGER_H
#define __ENCLAVE_KS_USER_MANAGER_H

#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include "User.h"

class UserManager
{
    public:
        static UserManager* Instance()
        {
            if(NULL == m_instance)
                m_instance = new UserManager();

            return m_instance;
        }

        void PushExchangeUser(const char* userpkeyhex, User user);
        bool PushAvaliableUser(const char* account, const char* userpkeyhex);
        void PushUserIndexMap(int index, std::string& strUserPkeyhex);
        void PushUserMailMap(int code, const char* mail);

        bool ExchangeUserExisted(const char* userpkeyhex);
        bool AvaliableUserExisted(const char* account);
        bool UserIndexExisted(int code);
        bool EmailIndexExisted(int code);

        void RemoveExchangeUser(const char* userpkeyHex);
        void RemoveAvaliableUser(const char* account);
        void RemoveUserIndex(int code);
        void RemoveUserMailIndex(int code);

        const char* GetShared(const char* account);
        const char* GetEmail(int code);
        User& GetUser(const char* account);

    private:
        UserManager(){}

    private:
        static UserManager* m_instance;

        //hex -> User
        std::map<std::string, User> m_userExchangedMap;
        //account->hex
        std::map<std::string, std::string> m_userAvaliableMap;
        //code -> hex
        std::map<int, std::string> m_userIndexMap;

        //code -> mail
        std::map<int, std::string> m_userMailMap;

};
#endif
