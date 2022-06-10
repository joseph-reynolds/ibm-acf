#include "CeLogin.h"
#include "CeLoginAsnV1.h"
#include "CeLoginJson.h"
#include "CeLoginUtil.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include <map>
#include <getopt.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#define SOURCE_FILE_VERSION 1
#define UNSET_SERIAL_NUM_KEYWORD "UNSET"
#define BLANK_SERIAL_NUMBER "       "

//RUN_UNIT_TESTS should only be enabled when running
//meson unit tests, otherwise this shoudn't be enabled
#ifdef RUN_UNIT_TESTS
#include "testconf.h"
// print logs to stdout under test
#define pam_syslog(X, Y, ...) printf(__VA_ARGS__)
#else
#include <sdbusplus/bus.hpp>
#define ACF_FILE_PATH "/etc/acf/service.acf"
#define PROD_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-prod.key"
#define PROD_BACKUP_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-prod-backup.key"
#define PROD_BACKUP2_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-prod-backup2.key"
#define DEV_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-dev.key"
#endif

// DBUS definitions for getting host's serial number property
#define DBUS_INVENTORY_SYSTEM_OBJECT "/xyz/openbmc_project/inventory/system"
#define DBUS_INVENTORY_ASSET_INTERFACE                                         \
    "xyz.openbmc_project.Inventory.Decorator.Asset"
#define DBUS_SERIAL_NUM_PROP "SerialNumber"

const char* default_user = "service";

using namespace std;
using namespace CeLogin;

// mapping of failure codes to messages
std::map<int, std::string> mapping = {
    {0x00, "Success"},
    {0x01, "Failure"},
    {0x02, "UnsupportedVersion"},
    {0x03, "SignatureNotValid"},
    {0x04, "PasswordNotValid"},
    {0x05, "AcfExpired"},
    {0x06, "SerialNumberMismatch"},
    {0x07, "JsonDataAllocationFailure"},

    {0x13, "CreateHsf_PasswordHashFailure"},
    {0x14, "CreateHsf_JsonHashFailure"},

    {0x20, "DecodeHsf_AsnDecodeFailure"},
    {0x21, "DecodeHsf_OidMismatchFailure"},
    {0x22, "DecodeHsf_CreateJsonDigestFailure"},
    {0x23, "DecodeHsf_PublicKeyAllocFailure"},
    {0x24, "DecodeHsf_PublicKeyImportFailure"},
    {0x25, "DecodeHsf_JsonParseFailure"},
    {0x26, "DecodeHsf_VersionMismatch"},
    {0x27, "DecodeHsf_ReadSerialNumberFailure"},
    {0x28, "DecodeHsf_ReadFrameworkEcFailure"},
    {0x29, "DecodeHsf_ReadMachineArrayFailure"},
    {0x2A, "DecodeHsf_MachineArrayInvalidLength"},
    {0x2B, "DecodeHsf_ReadHashedAuthCodeFailure"},
    {0x2C, "DecodeHsf_ReadExpirationFailure"},
    {0x2D, "DecodeHsf_ReadRequestIdFailure"},

    {0x30, "VerifyAcf_AsnDecodeFailure"},
    {0x31, "VerifyAcf_OidMismatchFailure"},
    {0x32, "VerifyAcf_CreateJsonDigestFailure"},
    {0x33, "VerifyAcf_PublicKeyAllocFailure"},
    {0x34, "VerifyAcf_PublicKeyImportFailure"},
    {0x35, "VerifyAcf_InvalidParm"},
    {0x36, "VerifyAcf_Asn1CopyFailure"},
    {0x37, "VerifyAcf_Nid2OidFailed"},
    {0x38, "VerifyAcf_ProcessingTypeMismatch"},

    {0x40, "DetermineAuth_PasswordHashFailure"},
    {0x41, "DetermineAuth_Asn1TimeAllocFailure"},
    {0x42, "DetermineAuth_Asn1TimeFromUnixFailure"},
    {0x43, "DetermineAuth_AsnAllocFailure"},
    {0x44, "DetermineAuth_Asn1TimeCompareFailure"},

    {0x50, "Util_ValueFromJsonTagFailure"},

    {0x60, "HexToBin_HexPairOverflow"},
    {0x61, "HexToBin_InvalidHexString"},

    {0x70, "DateFromString_StrtoulFailure"},
    {0x71, "DateFromString_InvalidFormat"},
    {0x72, "DateFromString_InvalidParm"},

    {0x80, "GetAsn1Time_SetStringFailure"},
    {0x81, "GetAsn1Time_FormatStringFailure"},
    {0x82, "GetAsn1Time_InvalidParm"},

    {0x90, "CreatePasswordHash_InvalidInputBuffer"},
    {0x91, "CreatePasswordHash_InvalidInputBufferLength"},
    {0x92, "CreatePasswordHash_InvalidOutputBuffer"},
    {0x93, "CreatePasswordHash_InvalidOutputBufferLength"},
    {0x94, "CreatePasswordHash_OsslCallFailed"},

    {0xA0, "CreateDigest_InvalidInputBuffer"},
    {0xA1, "CreateDigest_InvalidInputBufferLength"},
    {0xA2, "CreateDigest_InvalidOutputBuffer"},
    {0xA3, "CreateDigest_InvalidOutputBufferLength"},
    {0xA4, "CreateDigest_OsslCallFailed"},

    {0xB0, "GetUnsignedIntFromString_InvalidBuffer"},
    {0xB1, "GetUnsignedIntFromString_ZeroLengthBuffer"},
    {0xB2, "GetUnsignedIntFromString_IntegerOverflow"},
    {0xB3, "GetUnsignedIntFromString_InvalidString"},

    {0xC0, "GetAuthFromFrameworkEc_InvalidParm"},
};
enum verifyACFErrors
{
    verifyACF_NotInvoked = -1,
    verifyACF_FailedReadingACF = -2,
    verifyACF_FailedReadingKey = -3,
};


// Determine the user name of the auth attempt.
// Returns:
//    PAM_SUCCESS for the special service user.
//    {any retcode} if pam_get_user failed.
//    PAM_IGNORE otherwise.
int ignore_other_accounts(pam_handle_t* pamh, const char* user_parm)
{
    const char* login_user = NULL;
    int retval = pam_get_user(pamh, &login_user, NULL);
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_NOTICE, "Unable to get user name: %s\n",
                   pam_strerror(pamh, retval));
        return retval;
    }
    if (0 != strcmp(user_parm, login_user))
    {
        return PAM_IGNORE;
    }
    return PAM_SUCCESS;
}

bool readBinaryFile(const std::string fileNameParm,
                    std::vector<uint8_t>& bufferParm, pam_handle_t* pamh)
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

            sInputFile.read((char*)bufferParm.data(), size);
            sInputFile.close();

            return true;
        }
        else
        {
            pam_syslog(pamh, LOG_WARNING, "Failed to open file %s\n",
                       fileNameParm.c_str());
        }
    }
    else
    {
        pam_syslog(pamh, LOG_WARNING, "filename empty");
    }

    return false;
}

// Return value: one of verifyACFErrors or CeLogin::CeLoginRc.mReason
int verifyACF(string acfPubKeypath, const char* passwordParm, string mSerialNumber,
              pam_handle_t* pamh)
{
    string acfFileName = (ACF_FILE_PATH);
    vector<uint8_t> sAcf;
    time_t sTime = time(NULL);
    const uint64_t passwordLengthParm = strlen(passwordParm);
    const uint64_t timeSinceUnixEpocInSecondsParm = sTime;
    vector<uint8_t> sPublicKey;
    const char* serialNumberParm = mSerialNumber.data();
    const uint64_t serialNumberLengthParm = mSerialNumber.size();
    CeLogin::ServiceAuthority sAuth = CeLogin::ServiceAuth_None;

    uint64_t sExpiration = 0;
    if (readBinaryFile(acfFileName, sAcf, pamh))
    {
        if (readBinaryFile(acfPubKeypath, sPublicKey, pamh))
        {
            const uint8_t* publicKeyParm = (const uint8_t*)sPublicKey.data();
            const uint64_t publicKeyLengthParm = sPublicKey.size();

            const uint8_t* accessControlFileParm = sAcf.data();
            const uint64_t accessControlFileLengthParm = sAcf.size();

            CeLogin::CeLoginRc sRc = CeLogin::getServiceAuthorityV1(
                accessControlFileParm, accessControlFileLengthParm,
                passwordParm, passwordLengthParm,
                timeSinceUnixEpocInSecondsParm, publicKeyParm,
                publicKeyLengthParm, serialNumberParm, serialNumberLengthParm,
                sAuth, sExpiration);
            return sRc.mReason;
        }
        else
        {
            // A log entry was already sent for this
            return verifyACF_FailedReadingKey;
        }
    }
    else
    {
        // A log entry was already sent for this
        return verifyACF_FailedReadingACF;
    }
    return PAM_SUCCESS;
}
#ifdef RUN_UNIT_TESTS
int fieldModeEnabled = 1;
string mSerialNumber = "UNSET";
//manually set variables (fieldModeEnabled and mSerialNumber)
//for googletest for as dbus objects
//aren't available on non OpenBMC targets
void setFieldModeProperty(int fieldModeEnabledParam)
{
    fieldModeEnabled = fieldModeEnabledParam;
}

void setSerialNumberProperty(const string& obj){
    mSerialNumber = obj;
}
#else
int readFieldMode(pam_handle_t* pamh)
{
    FILE* pipe = popen("fw_printenv -n fieldmode 2>&1", "r");
    if (!pipe)
    {
        pam_syslog(pamh, LOG_ERR, "popen failed\n");
        return PAM_SYSTEM_ERR;
    }
    std::array<char, 512> buffer;
    std::stringstream result;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
    {
        result << buffer.data();
    }
    int stat = pclose(pipe);
    if (WIFEXITED(stat))
    {
        // Handle expected results
        int rc = WEXITSTATUS(stat);
        if (rc == 0)
        {
            // fw_printenv exited normally with rc=0
            if (0 == strcmp(result.str().c_str(), "true\n"))
            {
                return 1; // fieldmode=true
            }
            return 0; // any other value means fieldmode=false
        }
        // fw_printenv exited normally with nonzero rc
        if (0 == strcmp(result.str().c_str(),
                        "## Error: \"fieldmode\" not defined\n"))
        {
            return 0; // fieldmode not set means fieldmode=false
        }
    }
    // Something unexpected happened.  Either fw_printenv exited abnormally,
    // or gave unexpected results, or something else unexpected happened.
    pam_syslog(pamh, LOG_ERR, "pclose failed stat=0x%X, message=%s\n",
               stat, result.str().c_str());
    return -1; // This should never happen
}

string readMachineSerialNumberProperty(const string& obj, const string& inf,
                                       const string& prop, pam_handle_t* pamh)
{
    std::string propSerialNum = "";
    std::string object = obj;
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.Inventory.Manager", object.c_str(),
        "org.freedesktop.DBus.Properties", "Get");
    properties.append(inf);
    properties.append(prop);
    try
    {
        auto result = bus.call(properties);
        if (!result.is_method_error())
        {
            std::variant<string> val;
            result.read(val);
            if (auto pVal = std::get_if<string>(&val))
            {
                propSerialNum.assign((pVal->data()), pVal->size());
            }
            else
            {
                pam_syslog(pamh, LOG_ERR,
                           "could not get the host's serial number\n");
            }
        }
    }
    catch (const std::exception& exc)
    {
        pam_syslog(pamh, LOG_ERR,
                   "dbus call for getting serial number failed: %s\n",
                   exc.what());
        propSerialNum = "";
    }
    return propSerialNum;
}
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
#ifdef HAVE_PAM_FAIL_DELAY
    pam_fail_delay(pamh, 2'000'000);
#endif // HAVE_PAM_FAIL_DELAY

    const char* username = NULL;
    // Only handle the service user.
    int retval = -1;
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    else if (strcmp(default_user, username))
    {
        return PAM_IGNORE;
    }

    // Get the user's password
    const char* password;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_WARNING, "Unable to get password\n");
        return PAM_AUTH_ERR;
    }

    string acfDevPubKeypath = (DEV_PUB_KEY_FILE_PATH);
    string acfProdPubKeypath = (PROD_PUB_KEY_FILE_PATH);
    string acfProdBackupPubKeypath = (PROD_BACKUP_PUB_KEY_FILE_PATH);
    string acfProdBackup2PubKeypath = (PROD_BACKUP2_PUB_KEY_FILE_PATH);

    // Get host's serial number
#ifndef RUN_UNIT_TESTS
    string mSerialNumber = readMachineSerialNumberProperty(
        DBUS_INVENTORY_SYSTEM_OBJECT, DBUS_INVENTORY_ASSET_INTERFACE,
        DBUS_SERIAL_NUM_PROP, pamh);
#endif
    // If serial number is empty on machine set as UNSET for check with acf
    if (mSerialNumber.empty() || (mSerialNumber == BLANK_SERIAL_NUMBER))
    {
        mSerialNumber = UNSET_SERIAL_NUM_KEYWORD;
    }

    // Check the ACF with the production key.  There are three outcomes:
    //  1. Successful authentication.  Stop trying.
    //  2. Failure because cannot verify signature.  Try next signature.
    //  3. Failure because something else is wrong.  Stop trying.
    int sRc = verifyACF(acfProdPubKeypath, password, mSerialNumber, pamh);
    int sRc1 = sRc;
    int sRc2 = verifyACF_NotInvoked;
    int sRc3 = verifyACF_NotInvoked;
    int sRc4 = verifyACF_NotInvoked;
    int fieldMode = -1;
    if ((sRc == CeLoginRc::SignatureNotValid) || (sRc == verifyACF_FailedReadingKey))
    {
        // Check the ACF with the backup production key.
        sRc = verifyACF(acfProdBackupPubKeypath, password, mSerialNumber, pamh);
        sRc2 = sRc;

        if ((sRc == CeLoginRc::SignatureNotValid) || (sRc == verifyACF_FailedReadingKey))
        {
            // Check the ACF with the backup2 production key.
            sRc = verifyACF(acfProdBackup2PubKeypath, password, mSerialNumber, pamh);
            sRc3 = sRc;

            // If field mode is disabled, check the ACF with the development key.
            if ((sRc == CeLoginRc::SignatureNotValid) || (sRc == verifyACF_FailedReadingKey))
            {
                // Read the field mode value.
#ifndef RUN_UNIT_TESTS
                int fieldModeEnabled = readFieldMode(pamh);
#endif
                fieldMode = fieldModeEnabled;
                if (fieldModeEnabled == -1)
                {
                    pam_syslog(pamh, LOG_ERR,
                               "Could not read fieldmode value\n");
                    // Continue securely: as if field mode is enabled
                    fieldModeEnabled = 1;
                }
                if (fieldModeEnabled == 0)
                {
                    sRc = verifyACF(acfDevPubKeypath, password, mSerialNumber, pamh);
                    sRc4 = sRc;
                }
            }
        }
    }

    if (sRc == CeLoginRc::Success)
    {
        return PAM_SUCCESS;
    }

    // Log the error
    const char* errMsg = "";
    auto errIter = mapping.find(sRc);
    if (errIter != mapping.end())
    {
        errMsg = errIter->second.c_str();
    }
    if (sRc == verifyACF_FailedReadingACF)
    {
        errMsg = "FailedReadingACF";
    }
    pam_syslog(pamh, LOG_WARNING, "ACF service auth failed 0x%X: %s"
               " (serial=%s, sRc1=0x%X, sRc2=0x%0x, sRc3=0x%X, sRc4=0x%X)",
               sRc, errMsg, mSerialNumber.c_str(), sRc1, sRc2, sRc3, sRc4);
           
    if (sRc == verifyACF_FailedReadingACF || sRc == CeLoginRc::SignatureNotValid ||
        sRc == CeLoginRc::PasswordNotValid || sRc == CeLoginRc::AcfExpired ||
        sRc == CeLoginRc::SerialNumberMismatch)
    {
        return PAM_AUTH_ERR;
    }
    return PAM_SYSTEM_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc,
                              const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
    // Only handle the service user.
    const char* user_parm = default_user;
    int retval = ignore_other_accounts(pamh, user_parm);
    if (retval == PAM_IGNORE)
    {
        retval = PAM_PERM_DENIED;
    }
    return retval;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc,
                                    const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
    // Only handle the service user.  Reject all password changes.
    const char* user_parm = default_user;
    int retval = ignore_other_accounts(pamh, user_parm);
    switch(retval) {
        case PAM_SUCCESS:
            retval = PAM_AUTHTOK_ERR;
            break;

        case PAM_IGNORE:
            retval = PAM_SUCCESS;
            break;
    }

    return retval;
}
