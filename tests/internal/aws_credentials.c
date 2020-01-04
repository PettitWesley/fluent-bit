/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>

#include <monkey/mk_core.h>
#include <string.h>
#include <unistd.h>

#include "flb_tests_internal.h"

#define ACCESS_KEY "akid"
#define SECRET_KEY "skid"
#define TOKEN      "token"

static void unsetenv_credentials()
{
    int ret;

    ret = unsetenv(AWS_ACCESS_KEY_ID);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(AWS_SECRET_ACCESS_KEY);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(AWS_SESSION_TOKEN);
    if (ret < 0) {
        flb_errno();
        return;
    }
}

/* test for the env provider */
static void test_environment_provider()
{
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;

    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, ACCESS_KEY, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, SECRET_KEY, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, TOKEN, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = new_environment_provider();
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    unsetenv_credentials();

    aws_provider_destroy(provider);
}

/* test the env provider when no cred env vars are set */
static void test_environment_provider_unset()
{
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;

    unsetenv_credentials();


    provider = new_environment_provider();
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(creds == NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(creds == NULL);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    aws_provider_destroy(provider);
}

static void test_credential_expiration()
{
    struct tm tm = {0};
    /* one hour in the future */
    time_t exp_expected = time(NULL) + 3600;
    char time_stamp[50];
    time_t exp_actual;
    if (gmtime_r(&exp_expected, &tm) == NULL) {
        printf("gmtime didn't work");
    }
    if (strftime(time_stamp, 50, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        printf("strftime didn't work");
    }

    exp_actual = credential_expiration(time_stamp);

    TEST_CHECK(exp_actual == exp_expected);
}

TEST_LIST = {
    { "test_credential_expiration" , test_credential_expiration},
    { "environment_credential_provider" , test_environment_provider},
    { "environment_credential_provider_unset" ,
      test_environment_provider_unset},
    { 0 }
};
