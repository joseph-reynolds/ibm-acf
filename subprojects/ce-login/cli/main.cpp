
#include "CeLoginCli.h"
#include <CeLogin.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h> // getopt

#include <cinttypes>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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
            std::cout << "UT Framework Unimplemented" << std::endl;
            // TODO: Call test framework
        }
    }

    if (sPrintHelp)
    {
        std::cout << "Usage:" << std::endl;
        std::cout << "    " << argv[0] << " [create|decode|verify|test] <args>"
                  << std::endl;
        std::cout << std::endl;
        std::cout << "Command Help Text:" << std::endl;
        std::cout << "    " << argv[0]
                  << " [create|decode|verify|test] [-h|--help]" << std::endl;
    }
    return (int)sRc.mReason;
}
