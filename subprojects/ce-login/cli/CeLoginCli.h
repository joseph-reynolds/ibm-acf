
#include <CeLogin.h>

#ifndef _CELOGINCLI_H
#define _CELOGINCLI_H

namespace cli
{
    CeLogin::CeLoginRc createHsf(int argc, char** argv);
    CeLogin::CeLoginRc decodeHsf(int argc, char** argv);
    CeLogin::CeLoginRc verifyHsf(int argc, char** argv);
}; // namespace cli

#endif
