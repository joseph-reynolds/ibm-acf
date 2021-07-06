
#include "CeLoginCli.h"
#include "CliCeLoginV1.h"
#include "CliUtils.h"

#include <CeLogin.h>
#include <getopt.h>
#include <string.h>

#include <cinttypes>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

struct CreateArguments
{
    string mSourceFileName;
    vector<CeLogin::Machine> mMachines;
    string mPassword;
    string mExpirationDate;
    string mRequestId;
    string mPrivateKeyFile;
    string mOutputFile;
    bool mVerbose;
    bool mHelp;
    CreateArguments() : mVerbose(false), mHelp(false)
    {}
};

enum CreateOptOptions
{
    SourceFileName,
    Machine,
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
    {"sourceFileName", required_argument, NULL, 'f'},
    {"machine", required_argument, NULL, 'm'},
    {"password", required_argument, NULL, 'p'},
    {"expirationDate", required_argument, NULL, 'e'},
    {"requestId", required_argument, NULL, 'i'},
    {"pkey", required_argument, NULL, 'k'},
    {"output", required_argument, NULL, 'o'},
    {"help", no_argument, NULL, 'h'},
    {"verbose", no_argument, NULL, 'v'},
    {0, 0, 0, 0}};

string create_options_description[NOptOptions] = {
    "SourceFileName", "<processor gen>,<authority>,<serial number>",
    "Password",       "ExpirationDate",
    "RequestId",      "PrivateKeyFile",
    "OutputFile",     "Help",
    "Verbose"};

bool parseMachineFromString(const string& stringParm,
                            CeLogin::Machine& machineParm)
{
    bool sIsSuccess = false;

    size_t sCount = count(stringParm.begin(), stringParm.end(), ',');
    if (2 == sCount)
    {
        size_t sFirstDelimiter = stringParm.find(',');
        size_t sSecondDelimiter = stringParm.find(',', sFirstDelimiter + 1);

        string sProcStr = stringParm.substr(0, sFirstDelimiter);
        string sAuthStr = stringParm.substr(
            sFirstDelimiter + 1, sSecondDelimiter - sFirstDelimiter - 1);
        string sSerialStr = stringParm.substr(
            sSecondDelimiter + 1, stringParm.length() - sSecondDelimiter - 1);

        // TODO: force sProcStr and sAuthStr to a consistant case for better
        // parsing

        if (0 == sProcStr.compare("P10"))
        {
            CeLogin::ServiceAuthority sAuth = CeLogin::ServiceAuth_None;
            if (0 == sAuthStr.compare("dev"))
            {
                sAuth = CeLogin::ServiceAuth_Dev;
            }
            else if (0 == sAuthStr.compare("ce"))
            {
                sAuth = CeLogin::ServiceAuth_CE;
            }

            if (CeLogin::ServiceAuth_None != sAuth)
            {
                if (!sSerialStr.empty())
                {
                    machineParm.mAuth = sAuth;
                    machineParm.mProc = CeLogin::P10;
                    machineParm.mSerialNumber = sSerialStr;
                    sIsSuccess = true;
                }
            }
        }
    }
    return sIsSuccess;
}

void createParseArgs(int argc, char** argv, struct CreateArguments& args)
{
    string short_options = "";

    for (int i = 0; i < NOptOptions; i++)
    {
        short_options += create_long_options[i].val;
        if (required_argument == create_long_options[i].has_arg)
        {
            short_options += ":";
        }
    }

    int c;
    int sNumOfRequiredArgumentsFound = 0;
    while (1)
    {
        int option_index = 0;
        c = getopt_long(argc, argv, short_options.c_str(), create_long_options,
                        &option_index);
        if (c == -1)
            break;
        switch (c)
        {
            case 'f':
            {
                sNumOfRequiredArgumentsFound++;
                args.mSourceFileName = optarg;
                break;
            }
            case 'm':
            {
                sNumOfRequiredArgumentsFound++;
                // Expected format: <processor gen>,<authority>,<serial number>
                // Example: P10,Dev,12345
                string sArg = optarg;
                // Count the number of delimiters, should be 2
                CeLogin::Machine sMachine;
                if (parseMachineFromString(sArg, sMachine))
                {
                    args.mMachines.push_back(sMachine);
                }
                else
                {
                    cout << "ERROR: Unexpected string for machine type: \""
                         << sArg << "\"" << endl;
                }
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
            }
        }
    }
}

bool createValidateArgs(const CreateArguments& args)
{
    bool sIsValidArgs = true;
    if (args.mSourceFileName.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing SourceFileName" << endl;
    }
    if (args.mMachines.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing Machine Entry" << endl;
    }
    if (args.mPassword.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing Password" << endl;
    }
    if (args.mExpirationDate.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing ExpirationDate" << endl;
    }
    if (args.mRequestId.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing RequestId" << endl;
    }
    if (args.mPrivateKeyFile.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing PrivateKeyPath" << endl;
    }
    if (args.mOutputFile.empty())
    {
        sIsValidArgs = false;
        cout << "Error: Missing OutputFilePath" << endl;
    }
    return sIsValidArgs;
}

void createPrintHelp(int argc, char** argv)
{
    // Find the longest option
    size_t sLongestOpt = 0;
    for (unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(create_long_options[i].name);
        sLongestOpt = max<size_t>(sLongestOpt, sLength);
    }

    cout << "Usage: " << argv[0] << " " << argv[1] << endl;
    for (unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(create_long_options[i].name);
        cout << "\t-" << (char)create_long_options[i].val << " --"
             << create_long_options[i].name;
        for (size_t j = 0; j < (sLongestOpt - sLength); j++)
        {
            cout << " ";
        }
        cout << " | " << create_options_description[i] << endl;
    }
}

bool cli::createHsf(int argc, char** argv)
{
    CreateArguments sArgs;

    createParseArgs(argc - 1, argv + 1, sArgs);

    if (sArgs.mHelp)
    {
        createPrintHelp(argc, argv);
    }
    else if (createValidateArgs(sArgs))
    {
        CeLogin::CeLoginCreateHsfArgsV1 sCreateHsfArgs;

        sCreateHsfArgs.mSourceFileName = sArgs.mSourceFileName;

        sCreateHsfArgs.mMachines = sArgs.mMachines;

        sCreateHsfArgs.mPassword = sArgs.mPassword;

        sCreateHsfArgs.mExpirationDate = sArgs.mExpirationDate;

        sCreateHsfArgs.mRequestId = sArgs.mRequestId;

        vector<uint8_t> sKey;

        if (readBinaryFile(string(sArgs.mPrivateKeyFile), sKey))
        {
            sCreateHsfArgs.mPrivateKey = sKey;
        }

        vector<uint8_t> sAcfBinary;
        CeLogin::CeLoginRc sRc =
            CeLogin::createCeLoginAcfV1(sCreateHsfArgs, sAcfBinary);
        cout << "RC: " << hex << (int)sRc << endl;

        cout << sAcfBinary.size() << endl;

        if (!writeBinaryFile(sArgs.mOutputFile, sAcfBinary.data(),
                             sAcfBinary.size()))
        {
            cout << "Error in file" << endl;
        }
    }
    return true;
}
