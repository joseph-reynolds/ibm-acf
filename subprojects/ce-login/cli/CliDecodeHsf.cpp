
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <getopt.h>
#include <fstream>

#include <cinttypes>

#include <CeLogin.h>
#include "CliCeLoginV1.h"

#include "CliUtils.h"

#include "CeLoginCli.h"

using namespace CeLogin;

struct DecodeArguments
{
    const char* mHsfFileName;
    const char* mPublicKeyFileName;
    bool mVerbose;
    bool mHelp;
    DecodeArguments()
    {
        mHsfFileName = NULL;
        mPublicKeyFileName = NULL;
        mVerbose = false;
        mHelp = false;
    }
};

enum DecodeOptOptions
{
    HsfFileName,
    PublicKeyFileName,
    Help,
    Verbose,
    NOptOptions
};

struct option decode_long_options[NOptOptions + 1] = {
    {"hsfFile",        required_argument, NULL, 'i'},
    {"publicKeyFile",  required_argument, NULL, 'k'},
    {"help",           no_argument,       NULL, 'h'},
    {"verbose",        no_argument,       NULL, 'v'},
    {0,                0,                 0,     0}
};

std::string decode_options_description[NOptOptions] =
{
    "HsfFile",
    "PublicKeyFile",
    "Help",
    "Verbose"
};


void decodeParseArgs(int argc, char** argv, struct DecodeArguments& args)
{
    std::string short_options = "";

    for(int i = 0; i < NOptOptions; i++)
    {
        short_options += decode_long_options[i].val;
        if(required_argument == decode_long_options[i].has_arg)
        {
            short_options += ":";
        }
    }

    int c;
    int digit_optind = 0;
    int sNumOfRequiredArgumentsFound = 0;
    while(1)
    {
        int option_index = 0;
        c = getopt_long(argc, argv, short_options.c_str(), decode_long_options, &option_index);
        if (c == -1) break;
        switch (c)
        {
            case 'i':
            {
                sNumOfRequiredArgumentsFound++;
                args.mHsfFileName = optarg;
                break;
            }
            case 'k':
            {
                sNumOfRequiredArgumentsFound++;
                args.mPublicKeyFileName = optarg;
                break;
            }
            case 'h':
            {
                args.mHelp = true;
                break;
            }
            case 'v':
            {
                args.mVerbose = true;
                break;
            }
            default:
            {
            }
        }
    }
}

void decodePrintHelp(int argc, char** argv)
{
    // Find the longest option
    size_t sLongestOpt = 0;
    for(unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(decode_long_options[i].name);
        sLongestOpt = std::max<size_t>(sLongestOpt, sLength);
    }

    std::cout << "Usage: " << argv[0] << " " << argv[1] << std::endl;
    for(unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(decode_long_options[i].name);
        std::cout << "\t-" << (char)decode_long_options[i].val << " --" << decode_long_options[i].name;
        for(size_t j = 0; j < (sLongestOpt - sLength); j++)
        {
            std::cout << " ";
        }
        std::cout << " | " << decode_options_description[i] << std::endl;
    }
}

bool decodeValidateArgs(const DecodeArguments& args)
{
    bool sIsValidArgs = true;
    if(NULL == args.mHsfFileName)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing HsfFileName" << std::endl;
    }
    return sIsValidArgs;
}

void printDecodedHsf(const CeLogin::CeLoginDecryptedHsfArgsV1& hsfParm)
{
    std::cout << "{" << std::endl;
    std::cout << "\tProcessingType:\t" << hsfParm.mProcessingType << std::endl;
    std::cout << "\tSourceFileName:\t" << hsfParm.mSourceFileName << std::endl;
    std::cout << "\tSourceFileData:" << std::endl;
    std::cout << "\t{" << std::endl;
    std::cout << "\t\tserialNumber:\t" << hsfParm.mSerialNumber << std::endl;
    std::cout << "\t\tframeworkEc:\t" << hsfParm.mFrameworkEc << std::endl;
    std::cout << "\t\thashedAuthCode:\t" << hsfParm.mPasswordHash << std::endl;
    std::cout << "\t\texpiration:\t" << hsfParm.mExpirationDate << std::endl;
    std::cout << "\t\trequestId:\t" << hsfParm.mRequestId << std::endl;
    std::cout << "\t}" << std::endl;
    std::cout << "}" << std::endl;
}

bool cli::decodeHsf(int argc, char** argv)
{
    DecodeArguments sArgs;
    decodeParseArgs(argc, argv, sArgs);


    if(sArgs.mHelp)
    {
        decodePrintHelp(argc, argv);
    }
    else if(decodeValidateArgs(sArgs))
    {
        std::vector<uint8_t> sHsf;
        if(readBinaryFile(sArgs.mHsfFileName, sHsf))
        {
            if(sArgs.mPublicKeyFileName)
            {
                std::vector<uint8_t> sPublicKey;
                if(readBinaryFile(sArgs.mPublicKeyFileName, sPublicKey))
                {
                    CeLogin::CeLoginDecryptedHsfArgsV1 sDecodedHsf;
                    CeLogin::CeLoginRc sRc = CeLogin::decodeAndVerifyCeLoginHsfV1(sHsf,
                                                                                             sPublicKey,
                                                                                             sDecodedHsf);
                    if(CeLoginRc::Success == sRc)
                    {
                        printDecodedHsf(sDecodedHsf);
                        std::cout << "Signature verified" << std::endl;
                    }
                    else if(CeLoginRc::SignatureNotValid == sRc)
                    {
                        std::cout << "Signature is not valid" << std::endl;
                    }
                    else
                    {
                        std::cout << "Error: 0x" << std::hex << (int)sRc << std::endl;
                    }
                }
                else
                {
                    std::cout << "ERROR: Unable to read public key file: \""<< sArgs.mPublicKeyFileName << "\"" << std::endl;
                }
            }
            else
            {
                // Skip the signature validation step (should not be allowed on a system)
                std::cout << "Insecure decode " << std::endl;
            }
        }
        else
        {
            std::cout << "ERROR: Unable to read hsf file: \""<< sArgs.mHsfFileName << "\"" << std::endl;
        }

    }
    else
    {
        std::cout << "Args failed to validate" << std::endl;
    }


    return false;
}