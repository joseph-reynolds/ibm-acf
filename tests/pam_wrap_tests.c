#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif
#include "libpamtest.h"
#define SERVICE_NAME "pamtestservice"

#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif

#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif
static pam_handle_t *pamh;
int test_pam_authenticate(const char* password)
{
    printf("%s\n", __FUNCTION__);
    int pam_ret = PAM_SUCCESS;
	struct pamtest_conv_data conv_data;
	const char *authtoks[] = {
		password,
		NULL,
	};
	struct pam_testcase tests[] = {
		pam_test(PAMTEST_AUTHENTICATE, PAM_SUCCESS),
	};

	ZERO_STRUCT(conv_data);
	conv_data.in_echo_off = authtoks;

	run_pamtest(SERVICE_NAME, "service", &conv_data, tests, NULL);

    int i;
    for(i = 0; i < (sizeof(tests)/sizeof(tests[0])); i++){
        pam_ret = tests[i].op_rv;
        printf("tests[%d].op_rv = %d\n",i, pam_ret);
        if(pam_ret != PAM_SUCCESS) break;
    }

    printf("pam_err str = %s\n", pam_strerror(pamh, pam_ret));
    return pam_ret;
}

int test_pam_acct(const char* username)
{
    int pam_ret = PAM_SUCCESS;
    struct pam_testcase tests[] = {
        pam_test(PAMTEST_ACCOUNT, PAM_SUCCESS),
    };

    run_pamtest(SERVICE_NAME, username, NULL, tests, NULL);
    int i;
    for(i = 0; i < (sizeof(tests)/sizeof(tests[0])); i++){
        pam_ret = tests[i].op_rv;
        printf("tests[%d].op_rv = %d\n",i, pam_ret);
        if(pam_ret != PAM_SUCCESS) break;
    }

    printf("pam_err str = %s\n", pam_strerror(pamh, pam_ret));
    return pam_ret;
}

int test_pam_session(const char* username)
{
    int pam_ret = PAM_SUCCESS;
    const char *v;
    struct pam_testcase tests[] = {
        pam_test(PAMTEST_OPEN_SESSION, PAM_SUCCESS),
        pam_test(PAMTEST_GETENVLIST, PAM_SUCCESS),
        pam_test(PAMTEST_CLOSE_SESSION, PAM_SUCCESS),
        pam_test(PAMTEST_GETENVLIST, PAM_SUCCESS),
    };

    run_pamtest(SERVICE_NAME, username, NULL, tests, NULL);
    int i;
    for(i = 0; i < (sizeof(tests)/sizeof(tests[0])); i++){
        pam_ret = tests[i].op_rv;
        printf("tests[%d].op_rv = %d\n",i, pam_ret);
        if(pam_ret != PAM_SUCCESS) break;
    }

    printf("pam_err str = %s\n", pam_strerror(pamh, pam_ret));
    return pam_ret;
}

int test_pam_chauthtok(const char* username, const char* password)
{
    int pam_ret = PAM_SUCCESS;
    struct pamtest_conv_data conv_data;
    const char *authtoks[] = {
        password,
        NULL,
    };
    struct pam_testcase tests[] = {
        pam_test(PAMTEST_CHAUTHTOK, PAM_SUCCESS),
    };

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = authtoks;

    run_pamtest(SERVICE_NAME, username, &conv_data, tests, NULL);

    int i;
    for(i = 0; i < (sizeof(tests)/sizeof(tests[0])); i++){
        pam_ret = tests[i].op_rv;
        printf("tests[%d].op_rv = %d\n",i, pam_ret);
        if(pam_ret != PAM_SUCCESS) break;
    }

    printf("pam_err str = %s\n", pam_strerror(pamh, pam_ret));
    return pam_ret;
}
