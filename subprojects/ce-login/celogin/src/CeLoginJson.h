
#include <CeLogin.h>

#include "CeLoginUtil.h"

#ifndef _CELOGINJSON_H
#define _CELOGINJSON_H

namespace CeLogin
{

    extern const char* JsonName_Version;
    extern const char* JsonName_Machines;
    extern const char* JsonName_HashedAuthCode;
    extern const char* JsonName_Expiration;
    extern const char* JsonName_FrameworkEc;
    extern const char* JsonName_SerialNumber;

    struct CeLoginJsonData
    {
        unsigned int        version;
        ServiceAuthority    mRequestedAuthority;
        uint8_t               mHashedAuthCode[CeLogin_PasswordHashLength];
        CeLogin_Date        mExpirationDate;
    };

    CeLoginRc decodeJson(const char* jsonStringParm, const uint64_t jsonStringLengthParm,
                         const char* serialNumberParm, const uint64_t serialNumberLengthParm,
                         CeLoginJsonData& decodedJsonParm);

};

#endif