#include <limits.h>
#include "gtest/gtest.h"
#include <security/pam_modules.h>

extern void setFieldModeProperty(int);
extern void setSerialNumberProperty(const std::string&);
namespace {
extern "C" int test_pam_authenticate(const char* password);
extern "C" int test_pam_authenticate_incorrect_password(void);
extern "C" int test_pam_acct(const char*);
extern "C" int test_pam_chauthtok(const char* username, const char* password);
extern "C" int test_pam_session(const char* username);

TEST(Authenticate, pam_auth_positive_test) {
  EXPECT_EQ(0, test_pam_authenticate("0penBmc"));
}
TEST(Authenticate, pam_auth_incorrect_password) {
    setFieldModeProperty(1);
    EXPECT_EQ(PAM_AUTH_ERR, test_pam_authenticate("0penBmc123"));
}
TEST(Authenticate, pam_auth_incorrect_serial_number) {
    setFieldModeProperty(1);
    const std::string str = "abc123";
    setSerialNumberProperty(str);
    EXPECT_EQ(PAM_AUTH_ERR, test_pam_authenticate("0penBmc"));
}
TEST(Account, pam_account_service_user_test) {
    EXPECT_EQ(PAM_SUCCESS, test_pam_acct("service"));
}
TEST(Account, pam_account_root_user_test) {
    EXPECT_EQ(PAM_SUCCESS, test_pam_acct("root"));
}

TEST(Chauthtok, pam_chauthtok_service_user_test) {
    EXPECT_EQ(PAM_AUTHTOK_ERR, test_pam_chauthtok("service", "0penBmc"));
}
TEST(Chauthtok, pam_chauthtok_other_user_test) {
    EXPECT_EQ(PAM_SUCCESS, test_pam_chauthtok("notserviceuser", "0penBmc"));
}

TEST(Pam_Session, pam_session_service_test) {
    EXPECT_EQ(PAM_SUCCESS, test_pam_session("service"));
}

TEST(Pam_Session, pam_session_other_user_test) {
    EXPECT_EQ(PAM_SUCCESS, test_pam_session("notserviceuser"));
}
}

