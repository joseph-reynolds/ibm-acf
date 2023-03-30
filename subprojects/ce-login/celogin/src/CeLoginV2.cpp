#include "CeLoginAsnV1.h"
#include "CeLoginJson.h"
#include "CeLoginUtil.h"

#include <CeLogin.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

#include <new>

using CeLogin::CeLoginRc;
using CeLogin::CeLoginJsonData;
using CeLogin::CELoginSequenceV1;

// This common helper function performs three operations:
//   1. Verifies signature on ACF
//   2. Verifies ACF is not expired and is valid for this system
//   3. Fills out JSON data object with fiels in the ACF
//   4. Verifies replay ID if present and returns updated id
static CeLoginRc validateAndParseAcfV2(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, uint64_t& updatedReplayIdParm,
    CeLoginJsonData& outputJsonParm, uint64_t& expirationTimeParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    CELoginSequenceV1* sDecodedAsn = NULL;

    if (!accessControlFileParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfPtr;
    }
    else if (0 == accessControlFileLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfLength;
    }
    else if (!publicKeyParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyPtr;
    }
    else if (0 == publicKeyLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyLength;
    }
    else if (!serialNumberParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberPtr;
    }
    else if (0 == serialNumberLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberLength;
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
                         serialNumberLengthParm, outputJsonParm);
    }

    // Verify that the ACF has not expired (using UTC)
    if (CeLoginRc::Success == sRc)
    {
        sRc = isTimeExpired(&outputJsonParm, expirationTimeParm,
                            timeSinceUnixEpochInSecondsParm);
    }

    // Verify Replay ID
    if(CeLoginRc::Success == sRc)
    {
        // If we don't advance the replay ID, caller should persist the same value
        updatedReplayIdParm = currentReplayIdParm;

        if(outputJsonParm.mReplayInfo.mReplayIdPresent)
        {
	    const uint64_t& sAcfReplayId = outputJsonParm.mReplayInfo.mReplayId;

	    // The validity checks here depend on ACF type
            // Since a service ACF may be validated more than once, we will tolerate
            // a replay ID that is >= the persisted value. All other use cases (today)
            // require a strict inequality
            if(CeLogin::AcfType_Service == outputJsonParm.mType)
            {
                if(sAcfReplayId < currentReplayIdParm)
	        {
                    sRc = CeLoginRc::InvalidReplayId;
                }
            }
            else
            {
                if(sAcfReplayId <= currentReplayIdParm)
                {
                    sRc = CeLoginRc::InvalidReplayId;
                }
            }

	    if(CeLoginRc::Success == sRc)
	    {
                updatedReplayIdParm = sAcfReplayId;
            }
        }
    }

    if (sDecodedAsn)
    {
        CELoginSequenceV1_free(sDecodedAsn);
    }

    return sRc;
}

#ifndef CELOGIN_POWERVM_TARGET
CeLoginRc CeLogin::verifyACFForBMCUploadV2(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, uint64_t& updatedReplayIdParm,
    CeLogin::AcfType& acfTypeParm, uint64_t& expirationTimeParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    CeLoginJsonData* sJsonData = NULL;

    updatedReplayIdParm = 0;
    acfTypeParm = CeLogin::AcfType_Invalid;
    expirationTimeParm = 0;

    if (!accessControlFileParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfPtr;
    }
    else if (0 == accessControlFileLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfLength;
    }
    else if (!publicKeyParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyPtr;
    }
    else if (0 == publicKeyLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyLength;
    }
    else if (!serialNumberParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberPtr;
    }
    else if (0 == serialNumberLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberLength;
    }
    // No check for PW parms; may or may not be required.

    // Allocate on heap to avoid blowing the stack
    if (CeLoginRc::Success == sRc)
    {
        sJsonData = (CeLoginJsonData*)OPENSSL_malloc(sizeof(CeLoginJsonData));
        if (sJsonData)
        {
            new (sJsonData) CeLoginJsonData();
        }
        else
        {
            sRc = CeLoginRc::JsonDataAllocationFailure;
        }
    }

    // Stack copy to store the parsed expiration time into. Only pass back
    // the value if the authority has validated as CE or Dev.
    uint64_t sExpirationTime = 0;

    if (CeLoginRc::Success == sRc)
    {
        sRc = validateAndParseAcfV2(accessControlFileParm, accessControlFileLengthParm,
                timeSinceUnixEpochInSecondsParm, publicKeyParm, publicKeyLengthParm,
                serialNumberParm, serialNumberLengthParm,
                currentReplayIdParm, updatedReplayIdParm, *sJsonData, sExpirationTime);
    }

    // This interface only supports V1 and V2
    if (CeLoginRc::Success == sRc)
    {
        if (CeLogin::CeLoginVersion1 != sJsonData->mVersion &&
            CeLogin::CeLoginVersion2 != sJsonData->mVersion)
        {
            sRc = CeLoginRc::UnsupportedVersion;
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        acfTypeParm = sJsonData->mType;
        expirationTimeParm = sExpirationTime;
    }

    if (sJsonData)
    {
        sJsonData->~CeLoginJsonData();
        OPENSSL_free(sJsonData);
    }

    return sRc;
}
#endif /* CELOGIN_POWERVM_TARGET */

static CeLoginRc checkAuthorizationAndGetAcfUserFieldsV2Internal(
    const uint8_t* accessControlFileParm, const uint64_t accessControlFileLengthParm,
    const char* passwordParm, const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, uint64_t& updatedReplayIdParm,
    CeLogin::AcfUserFields& userFieldsParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    userFieldsParm.clear();

    CeLoginJsonData* sJsonData = NULL;

    if (!accessControlFileParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfPtr;
    }
    else if (0 == accessControlFileLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfLength;
    }
    else if (!publicKeyParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyPtr;
    }
    else if (0 == publicKeyLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyLength;
    }
    else if (!serialNumberParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberPtr;
    }
    else if (0 == serialNumberLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberLength;
    }
    // No check for PW parms; may or may not be required.

    // Allocate on heap to avoid blowing the stack
    if (CeLoginRc::Success == sRc)
    {
        sJsonData = (CeLoginJsonData*)OPENSSL_malloc(sizeof(CeLoginJsonData));
        if (sJsonData)
        {
            new (sJsonData) CeLoginJsonData();
        }
        else
        {
            sRc = CeLoginRc::JsonDataAllocationFailure;
        }
    }

    // Stack copy to store the parsed expiration time into. Only pass back
    // the value if the authority has validated as CE or Dev.
    uint64_t sExpirationTime = 0;

    if (CeLoginRc::Success == sRc)
    {
        sRc = validateAndParseAcfV2(accessControlFileParm, accessControlFileLengthParm,
                timeSinceUnixEpochInSecondsParm, publicKeyParm, publicKeyLengthParm,
                serialNumberParm, serialNumberLengthParm,
                currentReplayIdParm, updatedReplayIdParm, *sJsonData, sExpirationTime);
    }

    // This interface only supports V1 and V2
    if (CeLoginRc::Success == sRc)
    {
        if (CeLogin::CeLoginVersion1 != sJsonData->mVersion &&
            CeLogin::CeLoginVersion2 != sJsonData->mVersion)
        {
            sRc = CeLoginRc::UnsupportedVersion;
        }
    }

    // Need to verify the password for service ACF
    if (CeLoginRc::Success == sRc && CeLogin::AcfType_Service == sJsonData->mType)
    {
        if (!passwordParm)
        {
            sRc = CeLoginRc::GetSevAuth_InvalidPasswordPtr;
        }
        else if (0 == passwordLengthParm)
        {
            sRc = CeLoginRc::GetSevAuth_InvalidPasswordLength;
        }

        uint8_t sGeneratedAuthCode[CeLogin::CeLogin_MaxHashedAuthCodeLength];

        // Hash the provided ACF password
        if (CeLoginRc::Success == sRc)
        {
            sRc = CeLogin::createPasswordHash(
                passwordParm, passwordLengthParm, sJsonData->mAuthCodeSalt,
                sJsonData->mAuthCodeSaltLength, sJsonData->mIterations,
                sGeneratedAuthCode, sizeof(sGeneratedAuthCode),
                sJsonData->mHashedAuthCodeLength);
        }

        // Verify password hash matches the ACF hashed auth code
        if (CeLoginRc::Success == sRc)
        {
            if (0 != CRYPTO_memcmp(sGeneratedAuthCode,
                                   sJsonData->mHashedAuthCode,
                                   sJsonData->mHashedAuthCodeLength))
            {
                sRc = CeLoginRc::PasswordNotValid;
            }
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        userFieldsParm.mVersion = sJsonData->mVersion;
        userFieldsParm.mType = sJsonData->mType;
        userFieldsParm.mExpirationTime = sExpirationTime;

        if (CeLogin::AcfType_AdminReset == sJsonData->mType)
        {
            if (!sJsonData->mReplayInfo.mReplayIdPresent)
            {
                sRc = CeLoginRc::MissingReplayId;
            }
            else if (sJsonData->mAdminAuthCodeLength == 0 ||
                     sJsonData->mAdminAuthCodeLength >=
                         CeLogin::AdminAuthCodeMaxLen)
            {
                sRc = CeLoginRc::Failure;
            }
            else
            {
		// Reconstruct the ASCII version from hex
		sRc = CeLogin::getBinaryFromHex((const char*)sJsonData->mAdminAuthCode,
				                sJsonData->mAdminAuthCodeLength,
						(uint8_t*)userFieldsParm.mTypeSpecificFields.mAdminResetFields.mAdminAuthCode,
						CeLogin::AdminAuthCodeMaxLen,
						userFieldsParm.mTypeSpecificFields.mAdminResetFields.mAdminAuthCodeLength);
            }
        }
        else if (CeLogin::AcfType_Service == sJsonData->mType)
        {
            userFieldsParm.mTypeSpecificFields.mServiceFields.mAuth = sJsonData->mRequestedAuthority;
        }
    }

    if (sJsonData)
    {
        sJsonData->~CeLoginJsonData();
        OPENSSL_free(sJsonData);
    }

    return sRc;
}

#ifndef CELOGIN_POWERVM_TARGET
CeLoginRc CeLogin::checkAuthorizationAndGetAcfUserFieldsV2(
    const uint8_t* accessControlFileParm, const uint64_t accessControlFileLengthParm,
    const char* passwordParm, const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, AcfUserFields& userFieldsParm)
{
    uint64_t sOutputReplayId = 0;
    CeLoginRc sRc = checkAuthorizationAndGetAcfUserFieldsV2Internal(
        accessControlFileParm, accessControlFileLengthParm, passwordParm,
        passwordLengthParm, timeSinceUnixEpochInSecondsParm,
        publicKeyParm, publicKeyLengthParm, serialNumberParm,
        serialNumberLengthParm, currentReplayIdParm, sOutputReplayId,
        userFieldsParm);

    if(CeLoginRc::Success == sRc)
    {
        // On this interface, we require that the provided replay id match the
        // replay id in the ACF EXACTLY. The upload interface is responsible
        // for persisting the new value, so if we get this far, we know the
        // updated replay ID was never persisted.
        if(sOutputReplayId != currentReplayIdParm)
        {
            sRc = CeLoginRc::ReplayIdPersistenceFailure;
        }
    }

    return sRc;
}
#else
CeLoginRc CeLogin::checkAuthorizationAndGetAcfUserFieldsV2ForPowerVM(
    const uint8_t* accessControlFileParm, const uint64_t accessControlFileLengthParm,
    const char* passwordParm, const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, uint64_t& updatedReplayIdParm,
    AcfUserFields& userFieldsParm)
{
    return checkAuthorizationAndGetAcfUserFieldsV2Internal(
        accessControlFileParm, accessControlFileLengthParm, passwordParm,
        passwordLengthParm, timeSinceUnixEpochInSecondsParm,
        publicKeyParm, publicKeyLengthParm, serialNumberParm,
        serialNumberLengthParm, currentReplayIdParm, sOutputReplayId,
        userFieldsParm);
}
#endif /* CELOGIN_POWERVM_TARGET */
