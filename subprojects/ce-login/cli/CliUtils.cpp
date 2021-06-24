#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <cinttypes>
#include <sstream>

#include "CliUtils.h"

bool cli::readBinaryFile(const std::string fileNameParm, std::vector<uint8_t>& bufferParm)
{
    std::ifstream sInputFile;
    if (!fileNameParm.empty())
    {
        sInputFile.open(fileNameParm.c_str(), std::ios::in | std::ios::binary);
        if (sInputFile.is_open())
        {
            // Get the size of the file
            sInputFile.seekg(0, std::ios::end);
            std::streampos size = sInputFile.tellg();
            sInputFile.seekg(0, std::ios::beg);

            bufferParm.reserve(size);
            bufferParm.assign(size, 0);

            sInputFile.read((char *)bufferParm.data(), size);
            sInputFile.close();

            return true;
        }
        else
        {
            std::cout << "Failed to open file " << std::endl;
        }

    }
    else
    {
        std::cout << "filename empty" << std::endl;
    }

    return false;
}

bool cli::writeBinaryFile(const std::string fileNameParm,
                          const uint8_t* bufferParm, const uint64_t bufferLengthParm)
{
    std::ofstream sOutputFile;
    if (!fileNameParm.empty() && bufferParm)
    {
        sOutputFile.open(fileNameParm.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        if (sOutputFile.is_open())
        {
            sOutputFile.write((const char *)bufferParm, bufferLengthParm);
            sOutputFile.close();
            return true;
        }
    }
    return false;
}

std::string cli::getHexStringFromBinary(const std::vector<uint8_t>& binaryParm)
{
    std::stringstream ss;

    for(uint64_t sIdx = 0; sIdx < binaryParm.size(); sIdx++)
    {
        ss.fill('0');
        ss.width(2);
        ss << std::hex << (int)binaryParm[sIdx];
    }
    return ss.str();
}

bool cli::getIntFromJson(json_object* jsonObjectParm, const std::string keyParm, int32_t& resultIntParm)
{
    bool sSuccess = false;
    if(jsonObjectParm)
    {
        json_object* sSubObject = NULL;
        bool sResult = json_object_object_get_ex(jsonObjectParm, keyParm.data(), &sSubObject);
        if(sResult && sSubObject)
        {
            resultIntParm = json_object_get_int(sSubObject);
            sSuccess = true;
        }
    }
    return sSuccess;
}

bool cli::getStringFromJson(json_object* jsonObjectParm, const std::string keyParm, std::string& resultStringParm)
{
    bool sSuccess = false;
    if(jsonObjectParm)
    {
        json_object* sSubObject = NULL;
        bool sResult = json_object_object_get_ex(jsonObjectParm, keyParm.data(), &sSubObject);
        if(sResult && sSubObject)
        {
            const int sStringLength = json_object_get_string_len(sSubObject);
            if(sStringLength > 0)
            {
                const char* sString = json_object_get_string(sSubObject);
                resultStringParm = std::string(sString, sStringLength);
                sSuccess = true;
            }
        }
    }
    return sSuccess;
}
