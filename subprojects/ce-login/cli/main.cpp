
#include "CeLoginCli.h"
#include "CliUnitTest.h"

#include <CeLogin.h>
#include <getopt.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h> // getopt

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    bool sPrintHelp = true;

    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Failure;

    if (argc > 1)
    {
        if (0 == strcmp(argv[1], "create"))
        {
            sPrintHelp = false;
            sRc = cli::createHsf(argc, argv);
        }
        else if (0 == strcmp(argv[1], "create_prod"))
        {
            int version = 1;
            std::vector<char*> sArgv;

            for(int sIdx = 0; sIdx < argc; sIdx++)
            {
                std::string flag(argv[sIdx]);
                if(flag == "-v2" || flag == "-V2" || flag == "--v2" || flag == "--V2")
                {
                    version = 2;
                }
                else
                {
                    sArgv.push_back(argv[sIdx]);
                }
            }

            sPrintHelp = false;
            if(2 == version)
            {
                sRc = cli::createProductionHsfV2(sArgv.size(), sArgv.data());
            }
            else
            {
                sRc = cli::createProductionHsf(sArgv.size(), sArgv.data());
            }
        }
        else if (0 == strcmp(argv[1], "decode"))
        {
            sPrintHelp = false;
            sRc = cli::decodeHsf(argc, argv);
        }
        else if (0 == strcmp(argv[1], "verify"))
        {
            sPrintHelp = false;
            sRc = cli::verifyHsf(argc, argv);
        }
        else if (0 == strcmp(argv[1], "test"))
        {
            sPrintHelp = false;
            cli::unit_test_main(argc, argv);
        }
    }

    if (sPrintHelp)
    {
        std::cout << "Usage:" << std::endl;
        std::cout << "    " << argv[0]
                  << " [create_prod|create|decode|verify|test] [-v2] <args>"
                  << std::endl;
        std::cout << std::endl;
        std::cout << "Command Help Text:" << std::endl;
        std::cout << "    " << argv[0]
                  << " [create_prod|create|decode|verify|test] [-v2] [-h|--help]"
                  << std::endl;
    }
    return (int)sRc.mReason;
}
