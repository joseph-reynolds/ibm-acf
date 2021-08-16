
#include "CeLoginJson.h"

#include "JsmnUtils.h"

#include <CeLogin.h>
#include <string.h>

using namespace CeLogin;

namespace JsonUtils
{
enum JsonUtilsRc
{
    Success = CeLoginRc::Success,

    DecodeJson_JsmnParseFailed = 0x10,
    DecodeJson_JsonRootNotObject = 0x11,

    ParseDate_InvalidParm = 0x20,
    ParseDate_NotString = 0x21,

    ParseHashedAuth_InvalidParm = 0x30,
    ParseHashedAuth_NotString = 0x31,
    ParseHashedAuth_UnexpectedHashLength = 0x31,

    ParseAuthFromMachineArray_InvalidParm = 0x40,
    ParseAuthFromMachineArray_NotAnArray = 0x41,
    ParseAuthFromMachineArray_InvalidFrameworkEc = 0x42,

    ParseSalt_InvalidParm = 0x50,
    ParseSalt_NotString = 0x51,
    ParseSalt_SaltTooLong = 0x52,

    ParseIterations_InvalidParm = 0x60,
    ParseIterations_NotPrimitive = 0x61,
};

enum
{
    JsmnMaxNumTokens = 128,
};
}; // namespace JsonUtils

static CeLoginRc ParseDateFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                                    const uint64_t expirationTokenIdxParm,
                                    CeLogin_Date& dateParm);

static CeLoginRc ParseAuthorityFromMachineArrayToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t machineArrayTokenIdxParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm, ServiceAuthority& authorityParm);

static CeLoginRc ParseHashedAuthCodeFromToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t hashedAuthCodeTokenIdxParm, uint8_t* hashedAuthCodeParm,
    const uint64_t hashedAuthCodeSizeParm, uint64_t bytesWrittenParm);

static CeLoginRc ParseSaltFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                                    const uint64_t saltTokenIdxParm,
                                    uint8_t* saltParm,
                                    const uint64_t saltSizeParm,
                                    uint64_t& bytesWrittenParm);

static CeLoginRc
    ParseIterationsFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                             const uint64_t saltTokenIdxParm,
                             uint64_t& iterationsParm);

CeLoginRc CeLogin::decodeJson(const char* jsonStringParm,
                              const uint64_t jsonStringLengthParm,
                              const char* serialNumberParm,
                              const uint64_t serialNumberLengthParm,
                              CeLoginJsonData& decodedJsonParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    jsmn_parser sJsmnParser;
    jsmntok_t sJsmnTokens[JsonUtils::JsmnMaxNumTokens];

    jsmn_init(&sJsmnParser);
    int sNumTokens = jsmn_parse(&sJsmnParser, jsonStringParm,
                                jsonStringLengthParm, sJsmnTokens, 128);

    if (sNumTokens <= 0)
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::DecodeJson_JsmnParseFailed);
    }

    // This is a hardcoded parser. It expects the ACF JSON to look something
    // like this:
    // {
    //     "version":1,
    //     "machines":
    //         [
    //             { "serialNumber":"000020012345", "frameworkEc":"PWR10S" },
    //             { "serialNumber":"UNSET", "frameworkEc":"PWR10D" }
    //         ],
    //     "hashedAuthCode":"xxxxxxxx",
    //     “salt”:”xxxxxxxxx”,
    //     “iterations”:”10000”,
    //     "expiration":"2018-12-25",
    //     "requestId":"FACE0FF0"
    // }

    // Wrap the json string and tokens array in a nice way
    JsmnUtils::JsmnState sJsmnState;
    sJsmnState.mJsonString = jsonStringParm;
    sJsmnState.mJsonStringLength = jsonStringLengthParm;
    sJsmnState.mTokenArray = sJsmnTokens;
    sJsmnState.mTokenArrayLength = sNumTokens;

    // Step 1: Examine the top level entity. JSON only allows for a single
    // top-level entity. In the case of CeLogin, it must be an Object.
    if (CeLoginRc::Success == sRc)
    {
        if (JSMN_OBJECT != sJsmnTokens[0].type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::DecodeJson_JsonRootNotObject);
        }
    }

    // Step 2: Now that we know it is an Object, look for the "Names" associated
    // with all of the "Values" in the top level object. For CeLogin, the
    // top-level names we care about are:
    //      - "versions"
    //      - "machines"
    //      - "hashedAuthCode"
    //      - "expiration"
    //      - "salt"
    //      - "iterations"
    // Any others are ignored. If a duplicate is detected, then an error will be
    // returned.

    uint64_t sVersionIdx = 0;
    uint64_t sMachinesIdx = 0;
    uint64_t sHashedAuthCodeIdx = 0;
    uint64_t sSaltIdx = 0;
    uint64_t sIterationsIdx = 0;
    uint64_t sExpirationIdx = 0;

    const uint64_t sObjectTokenIdx = 0; // Index of the root token

    // Parse Version first, before parsing other things. Validate that the
    // version is correct before attempting to parse anything else
    if (CeLoginRc::Success == sRc)
    {
        uint64_t sVersion = CeLoginInvalidVersion;

        // Get the token for the version integer
        JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            sJsmnState, sObjectTokenIdx, JsonName_Version,
            strlen(JsonName_Version), sVersionIdx);
        sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

        // Parse the string from the token into an unsigned integer
        if (CeLoginRc::Success == sRc)
        {
            JsmnUtils::JsmnString sVersionString =
                sJsmnState.getString(sVersionIdx);
            sRc = getUnsignedIntegerFromString(sVersionString.mCharArray,
                                               sVersionString.mCharLength,
                                               sVersion);
        }

        // Determine if the version is supported
        if (CeLoginRc::Success == sRc)
        {
            if (CeLoginVersion1 != sVersion)
            {
                sRc = CeLoginRc::UnsupportedVersion;
            }
        }
    }

    // If there is ever a V2 JSON Payload, the rest of this logic should be
    // wrapped in function specific to V1 parsing.
    if (CeLoginRc::Success == sRc)
    {
        JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;

        if (JsmnUtils::Success == sJsmnRc)
        {
            sJsmnRc = JsmnUtils::ObjectGetValueByKey(
                sJsmnState, sObjectTokenIdx, JsonName_Machines,
                strlen(JsonName_Machines), sMachinesIdx);
        }

        if (JsmnUtils::Success == sJsmnRc)
        {
            sJsmnRc = JsmnUtils::ObjectGetValueByKey(
                sJsmnState, sObjectTokenIdx, JsonName_HashedAuthCode,
                strlen(JsonName_HashedAuthCode), sHashedAuthCodeIdx);
        }

        if (JsmnUtils::Success == sJsmnRc)
        {
            sJsmnRc = JsmnUtils::ObjectGetValueByKey(
                sJsmnState, sObjectTokenIdx, JsonName_Salt,
                strlen(JsonName_Salt), sSaltIdx);
        }

        if (JsmnUtils::Success == sJsmnRc)
        {
            sJsmnRc = JsmnUtils::ObjectGetValueByKey(
                sJsmnState, sObjectTokenIdx, JsonName_Iterations,
                strlen(JsonName_Iterations), sIterationsIdx);
        }

        if (JsmnUtils::Success == sJsmnRc)
        {
            sJsmnRc = JsmnUtils::ObjectGetValueByKey(
                sJsmnState, sObjectTokenIdx, JsonName_Expiration,
                strlen(JsonName_Expiration), sExpirationIdx);
        }
        // Automatically converts JsmnUtils::Success to CeLoginRc::Success
        sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
    }

    // parse expiration date
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseDateFromToken(sJsmnState, sExpirationIdx,
                                 decodedJsonParm.mExpirationDate);
    }

    // parse hashed auth code
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseHashedAuthCodeFromToken(
            sJsmnState, sHashedAuthCodeIdx, decodedJsonParm.mHashedAuthCode,
            sizeof(decodedJsonParm.mHashedAuthCode),
            decodedJsonParm.mHashedAuthCodeLength);
    }

    // parse salt
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseSaltFromToken(sJsmnState, sSaltIdx,
                                 decodedJsonParm.mAuthCodeSalt,
                                 sizeof(decodedJsonParm.mAuthCodeSalt),
                                 decodedJsonParm.mAuthCodeSaltLength);
    }

    // parse number of iterations
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseIterationsFromToken(sJsmnState, sIterationsIdx,
                                       decodedJsonParm.mIterations);
    }

    // parse machines
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseAuthorityFromMachineArrayToken(
            sJsmnState, sMachinesIdx, serialNumberParm, serialNumberLengthParm,
            decodedJsonParm.mRequestedAuthority);
    }
    return sRc;
}

CeLoginRc ParseDateFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                             const uint64_t expirationTokenIdxParm,
                             CeLogin_Date& dateParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(expirationTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseDate_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(expirationTokenIdxParm);

        if (JSMN_STRING != sTokenValue.type)
        {
            sRc =
                CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseDate_NotString);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(expirationTokenIdxParm);
            sRc = getDateFromString(sJsmnString.mCharArray,
                                    sJsmnString.mCharLength, dateParm);
        }
    }
    return sRc;
}

CeLoginRc ParseAuthorityFromMachineArrayToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t machineArrayTokenIdxParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm, ServiceAuthority& authorityParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(machineArrayTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::ParseAuthFromMachineArray_InvalidParm);
    }
    else
    {
        // Instead of trying to parse the entire machines array into some kind
        // of structure, scan it for the specific serial number that we care
        // about.
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(machineArrayTokenIdxParm);

        if (JSMN_ARRAY != sTokenValue.type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::ParseAuthFromMachineArray_NotAnArray);
        }
        else
        {
            bool sIsSerialNumberFound = false;
            const uint64_t sNumOfEntries = sTokenValue.size; // Array length
            uint64_t sCurIdx =
                machineArrayTokenIdxParm + 1; // Next token is the first element
            for (uint64_t sIdx = 0; sIdx < sNumOfEntries;
                 sIdx++) // Iterate over the array
            {
                // It should be an array of objects. Each object contains a
                // "serialNumber" and "frameworkEc" pair. First find the serial
                // number.
                uint64_t sSerialNumberIdx = 0;
                if (CeLoginRc::Success == sRc)
                {
                    JsmnUtils::JsmnUtilRc sJsmnRc =
                        JsmnUtils::ObjectGetValueByKey(
                            jsmnStateParm, sCurIdx, JsonName_SerialNumber,
                            strlen(JsonName_SerialNumber), sSerialNumberIdx);
                    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                }

                if (CeLoginRc::Success == sRc)
                {
                    // If the serial number was successfully read, compare to
                    // the requested serial number
                    JsmnUtils::JsmnString sSerialNumber =
                        jsmnStateParm.getString(sSerialNumberIdx);

                    if (JsmnUtils::SafeJsmnStringCompare(
                            sSerialNumber, serialNumberParm,
                            serialNumberLengthParm))
                    {
                        sIsSerialNumberFound = true;
                        // This is the entry for the current system
                        uint64_t sFrameworkEcIdx = 0;
                        {
                            // Locate the frameworkEc
                            JsmnUtils::JsmnUtilRc sJsmnRc =
                                JsmnUtils::ObjectGetValueByKey(
                                    jsmnStateParm, sCurIdx,
                                    JsonName_FrameworkEc,
                                    strlen(JsonName_FrameworkEc),
                                    sFrameworkEcIdx);
                            sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                        }

                        // If the frameworkEc was located, determine the service
                        // authority
                        if (CeLoginRc::Success == sRc)
                        {
                            JsmnUtils::JsmnString sFrameworkEc =
                                jsmnStateParm.getString(sFrameworkEcIdx);
                            sRc = CeLogin::getServiceAuthorityFromFrameworkEc(
                                sFrameworkEc.mCharArray,
                                sFrameworkEc.mCharLength, authorityParm);
                            // Regardless of the outcome, the serial number was
                            // located. Either we got an authority or an error
                            // occured. Stop looking.
                            break;
                        }
                    }
                }

                // If no errors, find the next array index
                if (CeLoginRc::Success == sRc)
                {
                    uint64_t sNextIdx = 0;
                    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::GetNextJsonEntry(
                        jsmnStateParm, sCurIdx, sNextIdx);
                    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                    sCurIdx = sNextIdx;
                }

                if (CeLoginRc::Success != sRc)
                {
                    // An error occurred this iteration, exit
                    break;
                }
            }
            if (CeLoginRc::Success == sRc && !sIsSerialNumberFound)
            {
                sRc = CeLoginRc::SerialNumberMismatch;
            }
        }
    }
    return sRc;
}

CeLoginRc ParseHashedAuthCodeFromToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t hashedAuthCodeTokenIdxParm, uint8_t* hashedAuthCodeParm,
    const uint64_t hashedAuthCodeSizeParm, uint64_t bytesWrittenParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    bytesWrittenParm = 0;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(hashedAuthCodeTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::ParseHashedAuth_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(hashedAuthCodeTokenIdxParm);

        if (JSMN_STRING != sTokenValue.type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::ParseHashedAuth_NotString);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(hashedAuthCodeTokenIdxParm);

            sRc = getBinaryFromHex(sJsmnString.mCharArray,
                                   sJsmnString.mCharLength, hashedAuthCodeParm,
                                   hashedAuthCodeSizeParm, bytesWrittenParm);

            if (CeLoginRc::Success == sRc &&
                CeLogin_MaxHashedAuthCodeLength < bytesWrittenParm)
            {
                sRc =
                    CeLoginRc(CeLoginRc::JsonUtils,
                              JsonUtils::ParseHashedAuth_UnexpectedHashLength);
            }
        }
    }
    return sRc;
}

CeLoginRc ParseSaltFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                             const uint64_t saltTokenIdxParm, uint8_t* saltParm,
                             const uint64_t saltSizeParm,
                             uint64_t& bytesWrittenParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    bytesWrittenParm = 0;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(saltTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseSalt_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue = jsmnStateParm.getToken(saltTokenIdxParm);

        if (JSMN_STRING != sTokenValue.type)
        {
            sRc =
                CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseSalt_NotString);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(saltTokenIdxParm);

            sRc = getBinaryFromHex(sJsmnString.mCharArray,
                                   sJsmnString.mCharLength, saltParm,
                                   saltSizeParm, bytesWrittenParm);

            if (CeLoginRc::Success == sRc &&
                CeLogin_MaxHashedAuthCodeSaltLength < bytesWrittenParm)
            {
                sRc = CeLoginRc(CeLoginRc::JsonUtils,
                                JsonUtils::ParseSalt_SaltTooLong);
            }
        }
    }
    return sRc;
}

CeLoginRc ParseIterationsFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                                   const uint64_t iterationsTokenIdxParm,
                                   uint64_t& iterationsParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(iterationsParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::ParseIterations_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(iterationsTokenIdxParm);

        if (JSMN_PRIMITIVE != sTokenValue.type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::ParseIterations_NotPrimitive);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(iterationsTokenIdxParm);

            sRc = getUnsignedIntegerFromString(sJsmnString.mCharArray,
                                               sJsmnString.mCharLength,
                                               iterationsParm);
        }
    }
    return sRc;
}
