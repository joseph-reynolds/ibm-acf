
#include "CeLoginAsnV1.h"
#include "CeLoginJson.h"
#include "CeLoginUtil.h"

#include <CeLogin.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

namespace CeLogin
{
const char* AcfProcessingType = "P";
};

CeLogin::CeLoginRc CeLogin::getServiceAuthorityV1(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const uint8_t* passwordParm,
    const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpocInSecondsParm, const uint8_t* publicKeyParm,
    const uint64_t publicKeyLengthParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm,
    CeLogin::ServiceAuthority& authorityParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    authorityParm = CeLogin::ServiceAuth_None;
    uint8_t sPasswordHash[CeLogin_PasswordHashLength];

    CELoginSequenceV1* sDecodedAsn = NULL;

    // Allocate on heap to avoid blowing the stack
    CeLoginJsonData* sJsonData = new CeLoginJsonData();

    if (!sJsonData)
    {
        sRc = CeLoginRc::JsonDataAllocationFailure;
    }

    if (CeLoginRc::Success == sRc)
    {
        // Returns a heap allocation of the decoded ANS1 structure.
        //  - Verify supported OID/signature algorithm
        //  - Verify expected ProcessingType
        //  - Verify signature over SourceFileData
        sRc = decodeAndVerifyAcf(accessControlFileParm,
                                 accessControlFileLengthParm, publicKeyParm,
                                 publicKeyLengthParm, sDecodedAsn);
    }

    // Verify system serial number is in machine list (and get the
    // authorization)
    if (CeLoginRc::Success == sRc)
    {
        sRc = decodeJson((const char*)sDecodedAsn->sourceFileData->data,
                         sDecodedAsn->sourceFileData->length, serialNumberParm,
                         serialNumberLengthParm, *sJsonData);
    }

    // Verify that the ACF has not expired (using UTC)
    if (CeLoginRc::Success == sRc)
    {
        ASN1_TIME* sAsn1CurTime = ASN1_TIME_new();
        ASN1_TIME* sAsn1ExpirationTime = ASN1_TIME_new();
        if (!sAsn1CurTime || !sAsn1ExpirationTime)
        {
            sRc = CeLoginRc::DetermineAuth_Asn1TimeAllocFailure;
        }
        else
        {
            sRc = getAsn1Time(sJsonData->mExpirationDate, sAsn1ExpirationTime);

            if (CeLoginRc::Success == sRc)
            {
                // returns a pointer to a time structure or NULL if an error
                // occurred.
                ASN1_TIME* sResult =
                    ASN1_TIME_set(sAsn1CurTime, timeSinceUnixEpocInSecondsParm);
                if (sResult != sAsn1CurTime)
                {
                    sRc = CeLoginRc::DetermineAuth_Asn1TimeFromUnixFailure;
                }
            }

            // returns -1 if a is before b, 0 if a equals b, or 1 if a is after
            // b. -2 is returned on error.
            const int sCompareResult =
                ASN1_TIME_compare(sAsn1CurTime, sAsn1ExpirationTime);

            if (1 == sCompareResult)
            {
                // The expiration date has passed
                sRc = CeLoginRc::AcfExpired;
            }
            else if (-2 == sCompareResult)
            {
                // A failure occurred in the comparison routine.
                sRc = CeLoginRc::DetermineAuth_Asn1TimeCompareFailure;
            }
        }

        if (sAsn1CurTime)
            ASN1_TIME_free(sAsn1CurTime);
        if (sAsn1ExpirationTime)
            ASN1_TIME_free(sAsn1ExpirationTime);
    }

    // Hash the provided ACF password
    if (CeLoginRc::Success == sRc)
    {
        sRc = createPasswordHash(passwordParm, passwordLengthParm,
                                 sPasswordHash, sizeof(sPasswordHash));
    }

    // Verify password hash matches the ACF hashed auth code
    if (CeLoginRc::Success == sRc)
    {
        if (0 != CRYPTO_memcmp(sPasswordHash, sJsonData->mHashedAuthCode,
                               CeLogin_PasswordHashLength))
        {
            sRc = CeLoginRc::PasswordNotValid;
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        authorityParm = sJsonData->mRequestedAuthority;
    }

    if (sDecodedAsn)
        CELoginSequenceV1_free(sDecodedAsn);
    if (sJsonData)
        delete sJsonData;

    return sRc;
}
