#include "CeLoginAsnV1.h"
#include "JsmnUtils.h"

#include <CeLogin.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#ifndef _CELOGINUTIL_H
#define _CELOGINUTIL_H

namespace CeLogin
{
extern const char* FrameworkEc_P10_Dev;
extern const char* FrameworkEc_P10_Service;

struct CeLogin_Date
{
    uint16_t mYear;
    uint8_t mMonth;
    uint8_t mDay;
};

enum
{
    CeLogin_Acf_NID = NID_sha512WithRSAEncryption,
    CeLogin_DigestLength = SHA512_DIGEST_LENGTH,
    CeLogin_PasswordHashLength = SHA512_DIGEST_LENGTH,

    CeLogin_MaxNumberOfJsonTokens = 128, // somewhat arbitrary right now
};

CeLoginRc getCeLoginRcFromJsmnRc(const JsmnUtils::JsmnUtilRc jsmnRc);

CeLoginRc getBinaryFromHex(const char* hexStringParm,
                           const uint64_t hexStringLengthParm,
                           uint8_t* binaryParm, const uint64_t binarySizeParm,
                           uint64_t& binaryLengthParm);

CeLoginRc getDateFromString(const char* dateStringParm,
                            const uint64_t dateStringLengthParm,
                            CeLogin_Date& dateParm);

CeLoginRc getAsn1Time(const CeLogin_Date& dateParm, ASN1_TIME* timeParm);

CeLoginRc decodeAndVerifyAcf(const uint8_t* accessControlFileParm,
                             const uint64_t accessControlFileLengthParm,
                             const uint8_t* publicKeyParm,
                             uint64_t publicKeyLengthParm,
                             CELoginSequenceV1*& decodedAsnParm);

CeLoginRc createDigest(const uint8_t* inputDataParm,
                       const uint64_t inputDataLengthParm,
                       uint8_t* outputHashParm,
                       const uint64_t outputHashSizeParm);

CeLoginRc createPasswordHash(const uint8_t* inputDataParm,
                             const uint64_t inputDataLengthParm,
                             uint8_t* outputHashParm,
                             const uint64_t outputHashSizeParm);

CeLoginRc getUnsignedIntegerFromString(const char* stringParm,
                                       const uint64_t stringLengthParm,
                                       uint64_t& integerParm);

CeLoginRc
    getServiceAuthorityFromFrameworkEc(const char* frameworkEcParm,
                                       const uint64_t frameworkEcLengthParm,
                                       ServiceAuthority& authParm);
}; // namespace CeLogin

#endif