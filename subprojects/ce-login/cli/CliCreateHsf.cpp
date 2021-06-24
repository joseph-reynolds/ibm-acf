
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <getopt.h>
#include <fstream>
#include <vector>

#include <cinttypes>

#include <CeLogin.h>

#include "CliUtils.h"
#include "CliCeLoginV1.h"

#include "CeLoginCli.h"

struct CreateArguments
{
    const char* mProcessingType;
    const char* mSourceFileName;
    const char* mSerialNumber;
    const char* mFrameworkEc;
    const char* mPassword;
    const char* mExpirationDate;
    const char* mRequestId;
    const char* mPrivateKeyFile;
    const char* mOutputFile;
    bool mVerbose;
    bool mHelp;
    CreateArguments()
    {
        mProcessingType = NULL;
        mSourceFileName = NULL;
        mSerialNumber = NULL;
        mFrameworkEc = NULL;
        mPassword = NULL;
        mExpirationDate = NULL;
        mRequestId = NULL;
        mPrivateKeyFile = NULL;
        mOutputFile = NULL;
        mVerbose = false;
        mHelp = false;
    }
};

enum CreateOptOptions
{
    ProcessingType,
    SourceFileName,
    SerialNumber,
    FrameworkEc,
    Password,
    ExpirationDate,
    RequestId,
    PrivateKeyFile,
    OutputFile,
    Help,
    Verbose,
    NOptOptions
};

struct option create_long_options[NOptOptions + 1] = {
    {"processingType", required_argument, NULL, 't'},
    {"sourceFileName", required_argument, NULL, 'f'},
    {"serialNumber",   required_argument, NULL, 's'},
    {"frameworkEc",    required_argument, NULL, 'c'},
    {"password",       required_argument, NULL, 'p'},
    {"expirationDate", required_argument, NULL, 'e'},
    {"requestId",      required_argument, NULL, 'i'},
    {"pkey",           required_argument, NULL, 'k'},
    {"output",         required_argument, NULL, 'o'},
    {"help",           no_argument,       NULL, 'h'},
    {"verbose",        no_argument,       NULL, 'v'},
    {0,                0,                 0,     0}
};

std::string create_options_description[NOptOptions] =
{
    "ProcessingType",
    "SourceFileName",
    "SerialNumber",
    "FrameworkEc",
    "Password",
    "ExpirationDate",
    "RequestId",
    "PrivateKeyFile",
    "OutputFile",
    "Help",
    "Verbose"
};


void createParseArgs(int argc, char** argv, struct CreateArguments& args)
{
    std::string short_options = "";

    for(int i = 0; i < NOptOptions; i++)
    {
        short_options += create_long_options[i].val;
        if(required_argument == create_long_options[i].has_arg)
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
        c = getopt_long(argc, argv, short_options.c_str(), create_long_options, &option_index);
        if (c == -1) break;
        switch (c)
        {
            case 't':
            {
                sNumOfRequiredArgumentsFound++;
                args.mProcessingType = optarg;
                break;
            }
            case 'f':
            {
                sNumOfRequiredArgumentsFound++;
                args.mSourceFileName = optarg;
                break;
            }
            case 's':
            {
                sNumOfRequiredArgumentsFound++;
                args.mSerialNumber = optarg;
                break;
            }
            case 'c':
            {
                sNumOfRequiredArgumentsFound++;
                args.mFrameworkEc = optarg;
                break;
            }
            case 'p':
            {
                sNumOfRequiredArgumentsFound++;
                args.mPassword = optarg;
                break;
            }
            case 'e':
            {
                sNumOfRequiredArgumentsFound++;
                args.mExpirationDate = optarg;
                break;
            }
            case 'i':
            {
                sNumOfRequiredArgumentsFound++;
                args.mRequestId = optarg;
                break;
            }
            case 'k':
            {
                sNumOfRequiredArgumentsFound++;
                args.mPrivateKeyFile = optarg;
                break;
            }
            case 'o':
            {
                sNumOfRequiredArgumentsFound++;
                args.mOutputFile = optarg;
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
                std::cout << "Unknown";
            }
        }
    }
}

bool createValidateArgs(const CreateArguments& args)
{
    bool sIsValidArgs = true;
    if(NULL == args.mProcessingType)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing Processing Type" << std::endl;
    }
    if(NULL == args.mSourceFileName)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing SourceFileName" << std::endl;
    }
    if(NULL == args.mSerialNumber)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing SerialNumber" << std::endl;
    }
    if(NULL == args.mFrameworkEc)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing FrameworkEc" << std::endl;
    }
    if(NULL == args.mPassword)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing Password" << std::endl;
    }
    if(NULL == args.mExpirationDate)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing ExpirationDate" << std::endl;
    }
    if(NULL == args.mRequestId)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing RequestId" << std::endl;
    }
    if(NULL == args.mPrivateKeyFile)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing PrivateKeyPath" << std::endl;
    }
    if(NULL == args.mOutputFile)
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing OutputFilePath" << std::endl;
    }
    return sIsValidArgs;
}

void createPrintHelp(int argc, char** argv)
{
    // Find the longest option
    size_t sLongestOpt = 0;
    for(unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(create_long_options[i].name);
        sLongestOpt = std::max<size_t>(sLongestOpt, sLength);
    }

    std::cout << "Usage: " << argv[0] << " " << argv[1] << std::endl;
    for(unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(create_long_options[i].name);
        std::cout << "\t-" << (char)create_long_options[i].val << " --" << create_long_options[i].name;
        for(size_t j = 0; j < (sLongestOpt - sLength); j++)
        {
            std::cout << " ";
        }
        std::cout << " | " << create_options_description[i] << std::endl;
    }
}

bool cli::createHsf(int argc, char** argv)
{
    CreateArguments sArgs;

    createParseArgs(argc - 1, argv + 1, sArgs);

    if(sArgs.mHelp)
    {
        createPrintHelp(argc, argv);
    }
    else if(createValidateArgs(sArgs))
    {
        CeLogin::CeLoginCreateHsfArgsV1 sCreateHsfArgs;

        sCreateHsfArgs.mProcessingType = sArgs.mProcessingType;

        sCreateHsfArgs.mSourceFileName = sArgs.mSourceFileName;

        sCreateHsfArgs.mSerialNumber = sArgs.mSerialNumber;

        sCreateHsfArgs.mFrameworkEc = sArgs.mFrameworkEc;

        sCreateHsfArgs.mPassword = std::vector<uint8_t>((uint8_t*)sArgs.mPassword, (uint8_t*)sArgs.mPassword + strlen(sArgs.mPassword));

        sCreateHsfArgs.mExpirationDate = sArgs.mExpirationDate;

        sCreateHsfArgs.mRequestId = sArgs.mRequestId;

        std::vector<uint8_t> sKey;

        if(readBinaryFile(std::string(sArgs.mPrivateKeyFile), sKey))
        {
            sCreateHsfArgs.mPrivateKey = sKey;
        }

        std::vector<uint8_t> sAcfBinary;
        CeLogin::CeLoginRc sRc = CeLogin::createCeLoginAcfV1(sCreateHsfArgs, sAcfBinary);
        std::cout << "RC: " << std::hex << (int)sRc << std::endl;

        std::cout << sAcfBinary.size() << std::endl;

        if(!writeBinaryFile(sArgs.mOutputFile, sAcfBinary.data(), sAcfBinary.size()))
        {
            std::cout << "Error in file" << std::endl;
        }

    }



    return true;
}