
#include <string>
#include <vector>
#include <CeLogin.h>

#ifndef _CELOGINV1_H
#define _CELOGINV1_H

namespace CeLogin
{
    struct CeLoginCreateHsfArgsV1
    {
        std::string mProcessingType;
        std::string mSourceFileName;
        std::string mSerialNumber;
        std::string mFrameworkEc;
        std::string mExpirationDate;
        std::string mRequestId;
        std::vector<uint8_t> mPassword;
        std::vector<uint8_t> mPrivateKey;
    };

    struct CeLoginDecryptedHsfArgsV1
    {
        std::string mProcessingType;
        std::string mSourceFileName;
        std::string mSerialNumber;
        std::string mFrameworkEc;
        std::string mExpirationDate;
        std::string mRequestId;
        std::string mPasswordHash;
    };


    CeLoginRc createCeLoginAcfV1(const CeLoginCreateHsfArgsV1& argsParm,
                                 std::vector<uint8_t>& generatedAcfParm);

    CeLoginRc decodeAndVerifyCeLoginHsfV1(const std::vector<uint8_t>& hsfParm,
                                          const std::vector<uint8_t>& publicKeyParm,
                                          CeLoginDecryptedHsfArgsV1& decodedHsfParm);

};

#endif