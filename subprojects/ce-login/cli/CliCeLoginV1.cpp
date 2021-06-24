#include <json-c/json.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/sha.h>
#include "openssl/rsa.h"
#include "openssl/obj_mac.h"
#include "openssl/objects.h"
#include "openssl/x509.h" // Needed for reading in public key
#include <string.h>
#include <cinttypes>
#include <CeLogin.h>
#include "../celogin/src/CeLoginAsnV1.h"

#include <sstream>
#include <iostream>

#include "../celogin/src/CeLoginUtil.h"

#include "CliUtils.h"

#include "CliCeLoginV1.h"

#include <iostream>
#include <vector>

CeLogin::CeLoginRc CeLogin::createCeLoginAcfV1(const CeLoginCreateHsfArgsV1& argsParm,
                                               std::vector<uint8_t>& generatedAcfParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    std::string sPasswordHashHexString;

    std::string sJsonString;
    std::vector<uint8_t> sJsonDigest(SHA512_DIGEST_LENGTH);
    std::vector<uint8_t> sJsonSignature;

    CELoginSequenceV1* sHsfStruct = NULL;

    uint8_t* sHsfDerEncoded = NULL;
    uint64_t sHsfDerEncodedLength = 0;

    if(argsParm.mProcessingType.empty()
        || argsParm.mSourceFileName.empty()
        || argsParm.mSerialNumber.empty()
        || argsParm.mFrameworkEc.empty()
        || argsParm.mPassword.empty()
        || argsParm.mExpirationDate.empty()
        || argsParm.mRequestId.empty())
    {
        sRc = CeLoginRc::Failure;
        std::cout << "ERROR line " << __LINE__ << std::endl;
    }

    // Hash password
    if(CeLoginRc::Success == sRc)
    {
        std::vector<uint8_t> sPasswordHash(SHA512_DIGEST_LENGTH);
        uint8_t* sResult = SHA512(argsParm.mPassword.data(), argsParm.mPassword.size(), sPasswordHash.data());
        if(sResult == sPasswordHash.data())
        {
            sPasswordHashHexString = cli::getHexStringFromBinary(sPasswordHash);
        }
        else
        {
            sRc = CeLoginRc::CreateHsf_PasswordHashFailure;
        }
    }

    // Create json structure
    if(CeLoginRc::Success == sRc)
    {
        json_object* sJsonObj        = json_object_new_object();
        json_object* sVersion        = json_object_new_int(CeLoginVersion1);
        json_object* sMachinesArray  = json_object_new_array();
        json_object* sMachinesObj    = json_object_new_object();

        json_object* sSerialNumber   = json_object_new_string(argsParm.mSerialNumber.c_str());
        json_object* sFrameworkEc    = json_object_new_string(argsParm.mFrameworkEc.c_str());
        json_object* sHashedPassword = json_object_new_string(sPasswordHashHexString.c_str());
        json_object* sExpirationDate = json_object_new_string(argsParm.mExpirationDate.c_str());
        json_object* sRequestId      = json_object_new_string(argsParm.mRequestId.c_str());
        json_object* sAuthority      = json_object_new_string("dev");

        if(sJsonObj && sVersion && sMachinesArray && sMachinesObj && sSerialNumber
            && sFrameworkEc && sHashedPassword && sExpirationDate && sRequestId)
        {
            json_object_object_add(sMachinesObj, "serialNumber", sSerialNumber);
            json_object_object_add(sMachinesObj, "frameworkEc", sFrameworkEc);
            json_object_array_add(sMachinesArray, sMachinesObj);

            json_object* sSecondMachine = json_object_new_object();
            json_object_object_add(sSecondMachine, "serialNumber", json_object_new_string("q2345"));
            json_object_object_add(sSecondMachine, "frameworkEc", json_object_new_string("PWR10S"));
            json_object_array_add(sMachinesArray, sSecondMachine);


            json_object_object_add(sJsonObj, "version", sVersion);
            json_object_object_add(sJsonObj, "machines", sMachinesArray);
            json_object_object_add(sJsonObj, "hashedAuthCode", sHashedPassword);
            json_object_object_add(sJsonObj, "expiration", sExpirationDate);
            json_object_object_add(sJsonObj, "requestId", sRequestId);
            json_object_object_add(sJsonObj, "authorityLevel", sAuthority);

            // When the json object is free'd this string will also be free'd
            const char* sGeneratedJsonString = json_object_to_json_string(sJsonObj);

            if(sGeneratedJsonString)
            {
                sJsonString = std::string(sGeneratedJsonString);
            }
            else
            {
                sRc = CeLoginRc::Failure;
            }

        }
        else
        {
            // deallocate memory
            if(sJsonObj)         {json_object_put(sJsonObj);         sJsonObj = NULL;}
            if(sVersion)         {json_object_put(sVersion);         sVersion = NULL;}
            if(sMachinesArray)   {json_object_put(sMachinesArray);   sMachinesArray = NULL;}
            if(sMachinesObj)     {json_object_put(sMachinesObj);     sMachinesObj = NULL;}
            if(sSerialNumber)    {json_object_put(sSerialNumber);    sSerialNumber = NULL;}
            if(sFrameworkEc)     {json_object_put(sFrameworkEc);     sFrameworkEc = NULL;}
            if(sHashedPassword)  {json_object_put(sHashedPassword);  sHashedPassword = NULL;}
            if(sExpirationDate)  {json_object_put(sExpirationDate);  sExpirationDate = NULL;}
            if(sRequestId)       {json_object_put(sRequestId);       sRequestId = NULL;}
            if(sAuthority)       {json_object_put(sAuthority);       sAuthority = NULL;}
        }

        if(sJsonObj)
        {
            json_object_put(sJsonObj);
            sJsonObj = NULL;
        }
    }

    if(CeLoginRc::Success == sRc && !sJsonString.empty())
    {
        uint8_t* sResult = SHA512((const uint8_t*)sJsonString.data(), sJsonString.size(), sJsonDigest.data());
        if(sResult != sJsonDigest.data())
        {
            sRc = CeLoginRc::CreateHsf_JsonHashFailure;
        }
    }

    if(CeLoginRc::Success == sRc)
    {
        const uint8_t* sConstPrivateKey = argsParm.mPrivateKey.data();
        RSA* sPrivateKey = d2i_RSAPrivateKey(NULL, &sConstPrivateKey, argsParm.mPrivateKey.size());
        // TODO: Verify size matches expected size
        if(sPrivateKey)
        {
            unsigned int sJsonSignatureSize = sJsonSignature.size();
            sJsonSignature = std::vector<uint8_t>(RSA_size(sPrivateKey));
            int result = RSA_sign(NID_sha512WithRSAEncryption,
                                  sJsonDigest.data(), sJsonDigest.size(),
                                  sJsonSignature.data(), &sJsonSignatureSize, sPrivateKey);
            if(1 != result)
            {
                sRc = CeLoginRc::Failure;
        std::cout << "ERROR line " << __LINE__ << std::endl;
            }
            else if(sJsonSignatureSize != sJsonSignature.size())
            {
                sRc = CeLoginRc::Failure;
            }
        }

        if(sPrivateKey)
        {
            RSA_free(sPrivateKey);
        }
    }

    if(CeLoginRc::Success == sRc)
    {
        sHsfStruct = CELoginSequenceV1_new();

        ASN1_STRING_set(sHsfStruct->processingType, argsParm.mProcessingType.c_str(), argsParm.mProcessingType.size());
        ASN1_STRING_set(sHsfStruct->sourceFileName, argsParm.mSourceFileName.c_str(), argsParm.mSourceFileName.size());
        ASN1_OCTET_STRING_set(sHsfStruct->sourceFileData, (const uint8_t*)sJsonString.data(), sJsonString.size());
        sHsfStruct->algorithm->id = OBJ_nid2obj(NID_sha512WithRSAEncryption);
        ASN1_BIT_STRING_set(sHsfStruct->signature, sJsonSignature.data(), sJsonSignature.size());

        std::vector<uint8_t> sHsfDerEncoded(2000);
        uint8_t* sDataPtr = sHsfDerEncoded.data();
        uint64_t sHsfDerEncodedLength = i2d_CELoginSequenceV1(sHsfStruct, &sDataPtr);
        if(sHsfDerEncodedLength > 0)
        {
            // Remove extra data from vector
            sHsfDerEncoded.erase(sHsfDerEncoded.begin() + sHsfDerEncodedLength, sHsfDerEncoded.end());
            generatedAcfParm = sHsfDerEncoded;
        }
        else
        {
            sRc = CeLoginRc::Failure;
        }

        CELoginSequenceV1_free(sHsfStruct);
    }

    return sRc;
}


CeLogin::CeLoginRc CeLogin::decodeAndVerifyCeLoginHsfV1(const std::vector<uint8_t>& hsfParm,
                                                                   const std::vector<uint8_t>& publicKeyParm,
                                                                   CeLoginDecryptedHsfArgsV1& decodedHsfParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    CELoginSequenceV1* sDecodedAsn = NULL;

    ASN1_OBJECT* sExpectedObject = OBJ_nid2obj(NID_sha512WithRSAEncryption);
    uint8_t sHashReceivedJson[SHA512_DIGEST_LENGTH];


    if(CeLoginRc::Success == sRc)
    {
        sRc = decodeAndVerifyAcf(hsfParm.data(), hsfParm.size(),
                                 publicKeyParm.data(), publicKeyParm.size(),
                                 sDecodedAsn);
    }


    if(CeLoginRc::Success == sRc)
    {
        decodedHsfParm.mProcessingType = std::string((const char*)sDecodedAsn->processingType->data,
                                                     sDecodedAsn->processingType->length);
        decodedHsfParm.mSourceFileName = std::string((const char*)sDecodedAsn->sourceFileName->data,
                                                     sDecodedAsn->sourceFileName->length);
    }

    if(CeLoginRc::Success == sRc)
    {
        std::cout << std::string((char*)sDecodedAsn->sourceFileData->data, sDecodedAsn->sourceFileData->length) << std::endl;
        json_object* sJson = json_tokener_parse((const char*)sDecodedAsn->sourceFileData->data);

        if(!sJson)
        {
            sRc = CeLoginRc::DecodeHsf_JsonParseFailure;
        }

        int32_t sVersion = 0;
        if(CeLoginRc::Success == sRc && cli::getIntFromJson(sJson, "version", sVersion))
        {
            if(CeLoginVersion1 != sVersion)
            {
                sRc = CeLoginRc::DecodeHsf_VersionMismatch;
            }
        }

        if(CeLoginRc::Success == sRc)
        {
            json_object* sMachinesArray  = NULL;
            json_object* sMachinesObj    = NULL;
            bool sMachineResult = json_object_object_get_ex(sJson, "machines", &sMachinesArray);
            if(sMachineResult && sMachinesArray)
            {
                if(1 == json_object_array_length(sMachinesArray))
                {
                    sMachinesObj = json_object_array_get_idx(sMachinesArray, 0);
                    if(sMachinesObj)
                    {
                        if(CeLoginRc::Success == sRc && !cli::getStringFromJson(sMachinesObj, "serialNumber", decodedHsfParm.mSerialNumber))
                        {
                            sRc = CeLoginRc::DecodeHsf_ReadSerialNumberFailure;
                        }
                        if(CeLoginRc::Success == sRc && !cli::getStringFromJson(sMachinesObj, "frameworkEc", decodedHsfParm.mFrameworkEc))
                        {
                            sRc = CeLoginRc::DecodeHsf_ReadFrameworkEcFailure;
                        }
                    }
                }
                else
                {
                    sRc = CeLoginRc::DecodeHsf_MachineArrayInvalidLength;
                }
            }
            else
            {
                sRc = CeLoginRc::DecodeHsf_ReadMachineArrayFailure;
            }
        }


        if(CeLoginRc::Success == sRc && !cli::getStringFromJson(sJson, "hashedAuthCode", decodedHsfParm.mPasswordHash))
        {
            sRc = CeLoginRc::DecodeHsf_ReadHashedAuthCodeFailure;
        }

        if(CeLoginRc::Success == sRc && !cli::getStringFromJson(sJson, "expiration", decodedHsfParm.mExpirationDate))
        {
            sRc = CeLoginRc::DecodeHsf_ReadExpirationFailure;
        }

        if(CeLoginRc::Success == sRc && !cli::getStringFromJson(sJson, "requestId", decodedHsfParm.mRequestId))
        {
            sRc = CeLoginRc::DecodeHsf_ReadRequestIdFailure;
        }

        if(sJson)
        {
            json_object_put(sJson);
        }

    }

    if(sDecodedAsn)
    {
        CELoginSequenceV1_free(sDecodedAsn);
    }
    return sRc;
}

