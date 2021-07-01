
#include "JsmnUtils.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

JsmnUtils::JsmnUtilRc JsmnUtils::GetNextJsonEntry(const JsmnState& jsmnState,
                                                  const uint64_t currentIdxParm,
                                                  uint64_t& nextIdxParm)
{
    JsmnUtilRc sRc = Success;
    if (!jsmnState.isValid() || !jsmnState.isTokenIdxValid(currentIdxParm))
    {
        sRc = GetNextJsonEntry_InvalidParm;
    }
    else
    {
        uint64_t sTokensRemaining = jsmnState.getToken(currentIdxParm).size;

        nextIdxParm = currentIdxParm + 1;
        while (sTokensRemaining > 0 && jsmnState.isTokenIdxValid(nextIdxParm))
        {
            sTokensRemaining += jsmnState.getToken(nextIdxParm).size;
            sTokensRemaining--;
            nextIdxParm++;
        }

        if (0 != sTokensRemaining && !jsmnState.isTokenIdxValid(nextIdxParm))
        {
            sRc = GetNextJsonEntry_BadWalk;
        }
    }
    return sRc;
}

void JsmnUtils::PrintJsmnToken(const JsmnState& jsmnStateParm,
                               const uint64_t tokenIdxParm)
{
    if (jsmnStateParm.isTokenIdxValid(tokenIdxParm))
    {
        const jsmntok_t& sToken = jsmnStateParm.getToken(tokenIdxParm);
        printf("{");
        switch (sToken.type)
        {
            case JSMN_UNDEFINED:
            {
                printf("JSMN_UNDEFINED,");
                break;
            }
            case JSMN_OBJECT:
            {
                printf("JSMN_OBJECT,");
                break;
            }
            case JSMN_ARRAY:
            {
                printf("JSMN_ARRAY,");
                break;
            }
            case JSMN_STRING:
            {
                printf("JSMN_STRING,");
                break;
            }
            case JSMN_PRIMITIVE:
            {
                printf("JSMN_PRIMITIVE,");
                break;
            }
            default:
            {
                printf("ERROR,");
                break;
            }
        }
        printf("%.*s", sToken.end - sToken.start,
               jsmnStateParm.mJsonString + sToken.start);
        printf("}\n");
    }
    else
    {
        printf("ERROR: Unable to print invalid JsmnToken %lu\n", tokenIdxParm);
    }
}

JsmnUtils::JsmnUtilRc JsmnUtils::ObjectGetValueByKey(
    const JsmnState& jsmnStateParm, const uint64_t objectRootIdxParm,
    const char* keyParm, const uint64_t keyLenParm, uint64_t& valueIdxParm)
{
    JsmnUtilRc sRc = Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(objectRootIdxParm) || !keyParm ||
        0 == keyLenParm ||
        JSMN_OBJECT != jsmnStateParm.getToken(objectRootIdxParm).type)
    {
        sRc = ObjectGetValueByKey_InvalidParm;
    }
    else if (0 == jsmnStateParm.getToken(objectRootIdxParm).size)
    {
        sRc = ObjectGetValueByKey_KeyNotFound;
    }
    else
    {
        bool sIsFound = false;
        uint64_t sFoundIdx = 0;

        uint64_t sTokenIdx =
            objectRootIdxParm + 1; // Next token after the top level object

        // Limit the number of iterations to prevent an infinite loop
        for (uint64_t sIter = objectRootIdxParm;
             sIter < jsmnStateParm.mTokenArrayLength; sIter++)
        {
            if (!jsmnStateParm.isTokenIdxValid(sTokenIdx))
            {
                break;
            }
            JsmnString sKey = jsmnStateParm.getString(sTokenIdx);

            if (SafeJsmnStringCompare(sKey, keyParm, keyLenParm))
            {
                if (!sIsFound)
                {
                    sIsFound = true;
                    sFoundIdx = sTokenIdx;
                }
                else
                {
                    sRc = ObjectGetValueByKey_DuplicateKeyFound;
                    break;
                }
            }

            uint64_t sNextTokenIdx = 0;
            // Will return the total token array length if the end is reached
            sRc = JsmnUtils::GetNextJsonEntry(jsmnStateParm, sTokenIdx,
                                              sNextTokenIdx);
            sTokenIdx = sNextTokenIdx;

            if (Success != sRc)
            {
                break;
            }
        }

        if (Success == sRc)
        {
            if (sIsFound)
            {
                // By definition, the found object should have size = 1 (the
                // value)
                if (1 == jsmnStateParm.getToken(sFoundIdx).size &&
                    jsmnStateParm.isTokenIdxValid(sFoundIdx + 1))
                {
                    valueIdxParm = sFoundIdx + 1;
                }
                else
                {
                    sRc = ObjectGetValueByKey_ObjectMissingValue;
                }
            }
            else
            {
                sRc = ObjectGetValueByKey_KeyNotFound;
            }
        }
    }
    return sRc;
}

bool JsmnUtils::SafeJsmnStringCompare(const JsmnString& jsmnStringParm,
                                      const char* stringParm,
                                      const uint64_t stringLengthParm)
{
    if (jsmnStringParm.mCharLength == stringLengthParm)
    {
        return 0 ==
               memcmp(jsmnStringParm.mCharArray, stringParm, stringLengthParm);
    }
    return false;
}
