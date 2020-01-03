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

#define EKS_ACCESS_KEY "eks_akid"
#define EKS_SECRET_KEY "eks_skid"
#define EKS_TOKEN      "eks_token"

#define STS_ACCESS_KEY "sts_akid"
#define STS_SECRET_KEY "sts_skid"
#define STS_TOKEN      "sts_token"

#define TOKEN_FILE_ENV_VAR            "AWS_WEB_IDENTITY_TOKEN_FILE"
#define ROLE_ARN_ENV_VAR              "AWS_ROLE_ARN"
#define SESSION_NAME_ENV_VAR          "AWS_ROLE_SESSION_NAME"

#define WEB_TOKEN_FILE "/data/aws_credentials/web_identity_token_file.txt"

#define STS_RESPONSE_EKS  "<AssumeRoleWithWebIdentityResponse \
xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\n\
  <AssumeRoleWithWebIdentityResult>\n\
    <SubjectFromWebIdentityToken>amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A\n\
</SubjectFromWebIdentityToken>\n\
    <Audience>client.5498841531868486423.1548@apps.example.com</Audience>\n\
    <AssumedRoleUser>\n\
      <Arn>arn:aws:sts::123456789012:assumed-role/WebIdentityRole/app1</Arn>\n\
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:app1</AssumedRoleId>\n\
    </AssumedRoleUser>\n\
    <Credentials>\n\
      <SessionToken>eks_token</SessionToken>\n\
      <SecretAccessKey>eks_skid</SecretAccessKey>\n\
      <Expiration>2014-10-24T23:00:23Z</Expiration>\n\
      <AccessKeyId>eks_akid</AccessKeyId>\n\
    </Credentials>\n\
    <Provider>www.amazon.com</Provider>\n\
  </AssumeRoleWithWebIdentityResult>\n\
  <ResponseMetadata>\n\
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>\n\
  </ResponseMetadata>\n\
</AssumeRoleWithWebIdentityResponse>"

#define STS_RESPONSE_ASSUME_ROLE "<AssumeRoleResponse \
xmlns=\"https://sts.amazonaws.com/doc/\n\
2011-06-15/\">\n\
  <AssumeRoleResult>\n\
    <AssumedRoleUser>\n\
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>\n\
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>\n\
    </AssumedRoleUser>\n\
    <Credentials>\n\
      <AccessKeyId>sts_akid</AccessKeyId>\n\
      <SecretAccessKey>sts_skid</SecretAccessKey>\n\
      <SessionToken>sts_token</SessionToken>\n\
      <Expiration>2019-11-09T13:34:41Z</Expiration>\n\
    </Credentials>\n\
    <PackedPolicySize>6</PackedPolicySize>\n\
  </AssumeRoleResult>\n\
  <ResponseMetadata>\n\
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>\n\
  </ResponseMetadata>\n\
</AssumeRoleResponse>"

/* Each test case has its own request function */
int request_eks_test1(struct aws_http_client *aws_client,
                      int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRoleWithWebIdentity") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/test")
               != NULL);
    TEST_CHECK(strstr(uri, "WebIdentityToken=this-is-a-fake-jwt") != NULL);
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") != NULL);

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = STS_RESPONSE_EKS;
    aws_client->c->resp.payload_size = strlen(STS_RESPONSE_EKS);
    aws_client->error_type = NULL;

    return 0;
}

int request_eks_random_session_name(struct aws_http_client *aws_client,
                                    int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRoleWithWebIdentity") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/test")
               != NULL);
    TEST_CHECK(strstr(uri, "WebIdentityToken=this-is-a-fake-jwt") != NULL);
    /* this test case has a random session name */
    TEST_CHECK(strstr(uri, "RoleSessionName=") != NULL);
    /* session name should not be the same as test 1 */
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") == NULL);

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = STS_RESPONSE_EKS;
    aws_client->c->resp.payload_size = strlen(STS_RESPONSE_EKS);
    aws_client->error_type = NULL;

    return 0;
}

int request_eks_api_error(struct aws_http_client *aws_client,
                          int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRoleWithWebIdentity") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/apierror")
               != NULL);
    TEST_CHECK(strstr(uri, "WebIdentityToken=this-is-a-fake-jwt") != NULL);
    /* this test case has a random session name */
    TEST_CHECK(strstr(uri, "RoleSessionName=") != NULL);
    /* session name should not be the same as test 1 */
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") == NULL);

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 500;
    aws_client->c->resp.payload = NULL;
    aws_client->c->resp.payload_size = 0;
    aws_client->error_type = NULL;

    return -1;
}

int request_sts_test1(struct aws_http_client *aws_client,
                      int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRole") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/test")
               != NULL);
    TEST_CHECK(strstr(uri, "ExternalId=external_id") != NULL);
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") != NULL);

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = STS_RESPONSE_ASSUME_ROLE;
    aws_client->c->resp.payload_size = strlen(STS_RESPONSE_ASSUME_ROLE);
    aws_client->error_type = NULL;

    return 0;
}

int request_sts_api_error(struct aws_http_client *aws_client,
                          int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRole") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/apierror")
               != NULL);
    TEST_CHECK(strstr(uri, "ExternalId=external_id") != NULL);
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") != NULL);

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 400;
    aws_client->c->resp.payload = NULL;
    aws_client->c->resp.payload_size = 0;
    aws_client->error_type = NULL;

    return 0;
}

/* test/mock version of the aws_http_client request function */
int test_http_client_request(struct aws_http_client *aws_client,
                             int method, const char *uri,
                             const char *body, size_t body_len,
                             struct aws_http_header *dynamic_headers,
                             size_t dynamic_headers_len)
{
    if (strcmp(aws_client->name, "sts_client_eks_provider") == 0) {
        /*
         * route to the correct test case fn using the uri - the role
         * name is different in each test case.
         */
        if (strstr(uri, "test1") != NULL) {
            return request_eks_test1(aws_client, method, uri);
        } else if (strstr(uri, "randomsession") != NULL) {
            return request_eks_random_session_name(aws_client, method, uri);
        } else if (strstr(uri, "apierror") != NULL) {
            return request_eks_api_error(aws_client, method, uri);
        }

        /* uri should match one of the above conditions */
        flb_errno();
        return -1;
    } else if (strcmp(aws_client->name, "sts_client_assume_role_provider") == 0)
    {
        if (strstr(uri, "test1") != NULL) {
            return request_sts_test1(aws_client, method, uri);
        } else if (strstr(uri, "apierror") != NULL) {
            return request_sts_api_error(aws_client, method, uri);
        }
        /* uri should match one of the above conditions */
        flb_errno();
        return -1;
    }

    /* client name should match one of the above conditions */
    flb_errno();
    return -1;

}

/* Test/mock aws_http_client */
static struct aws_http_client_vtable test_vtable = {
    .request = test_http_client_request,
};

struct aws_http_client *test_http_client_create()
{
    struct aws_http_client *client = flb_calloc(1,
                                                sizeof(struct aws_http_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &test_vtable;
    return client;
}

/* Generator that returns clients with the test vtable */
static struct aws_http_client_generator test_generator = {
    .new = test_http_client_create,
};

struct aws_http_client_generator *generator_in_test()
{
    return &test_generator;
}

static void unsetenv_eks()
{
    int ret;

    ret = unsetenv(TOKEN_FILE_ENV_VAR);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(ROLE_ARN_ENV_VAR);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(SESSION_NAME_ENV_VAR);
    if (ret < 0) {
        flb_errno();
        return;
    }
}

static void test_random_session_name()
{
    char *session_name = random_session_name();

    TEST_CHECK(strlen(session_name) == 32);
}

static void test_sts_uri()
{
    char *uri;

    uri = sts_uri("AssumeRole", "myrole", "mysession",
                  "myexternalid", NULL);
    TEST_CHECK(strcmp(uri, "/?Version=2011-06-15&Action=AssumeRole"
                      "&RoleSessionName=mysession&RoleArn=myrole"
                      "&ExternalId=myexternalid") == 0);
    flb_free(uri);
}

static void test_process_sts_response()
{
    struct aws_credentials *creds;
    time_t expiration;

    creds = process_sts_response(STS_RESPONSE_EKS, &expiration);

    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

}

static void test_eks_provider() {
    struct flb_config *config;
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    char path[4096];

    /* construct token file path */
    if (getcwd(path, sizeof(path)) == NULL) {
        flb_errno();
        return;
    }

    if (strcat(path, WEB_TOKEN_FILE) == NULL) {
        flb_errno();
        return;
    }

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    /* set env vars */
    ret = setenv(ROLE_ARN_ENV_VAR, "arn:aws:iam::123456789012:role/test1", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(SESSION_NAME_ENV_VAR, "session_name", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, path, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = new_eks_provider(config, NULL, "us-west-2", NULL,
                                generator_in_test());

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    aws_provider_destroy(provider);
    unsetenv_eks();
}

static void test_eks_provider_random_session_name() {
    struct flb_config *config;
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    char path[4096];

    /* construct token file path */
    if (getcwd(path, sizeof(path)) == NULL) {
        flb_errno();
        return;
    }

    if (strcat(path, WEB_TOKEN_FILE) == NULL) {
        flb_errno();
        return;
    }

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    /* set env vars - session name is not set */
    unsetenv_eks();
    ret = setenv(ROLE_ARN_ENV_VAR,
                 "arn:aws:iam::123456789012:role/randomsession", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, path, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = new_eks_provider(config, NULL, "us-west-2", NULL,
                                generator_in_test());

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    aws_provider_destroy(provider);
    unsetenv_eks();
}

static void test_eks_provider_api_error() {
    struct flb_config *config;
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    char path[4096];

    /* construct token file path */
    if (getcwd(path, sizeof(path)) == NULL) {
        flb_errno();
        return;
    }

    if (strcat(path, WEB_TOKEN_FILE) == NULL) {
        flb_errno();
        return;
    }

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    unsetenv_eks();
    ret = setenv(ROLE_ARN_ENV_VAR, "arn:aws:iam::123456789012:role/apierror",
                 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, path, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = new_eks_provider(config, NULL, "us-west-2", NULL,
                                generator_in_test());

    /* API will return an error - creds will be NULL */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    aws_provider_destroy(provider);
    unsetenv_eks();
}

static void test_sts_provider() {
    struct flb_config *config;
    struct aws_credentials_provider *provider;
    struct aws_credentials_provider *base_provider;
    struct aws_credentials *creds;
    int ret;

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    /* use the env provider as the base provider */
    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, "base_akid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, "base_skid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, "base_token", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    base_provider = new_environment_provider();
    if (!base_provider) {
        flb_errno();
        return;
    }

    provider = new_sts_provider(config, NULL, base_provider, "external_id",
                                "arn:aws:iam::123456789012:role/test1",
                                "session_name", "cn-north-1", NULL,
                                generator_in_test());
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
    TEST_CHECK(strcmp(STS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(STS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(STS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(STS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(STS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(STS_TOKEN, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    aws_provider_destroy(base_provider);
    aws_provider_destroy(provider);
}

static void test_sts_provider_api_error() {
    struct flb_config *config;
    struct aws_credentials_provider *provider;
    struct aws_credentials_provider *base_provider;
    struct aws_credentials *creds;
    int ret;

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    /* use the env provider as the base provider */
    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, "base_akid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, "base_skid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, "base_token", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    base_provider = new_environment_provider();
    if (!base_provider) {
        flb_errno();
        return;
    }

    provider = new_sts_provider(config, NULL, base_provider, "external_id",
                                "arn:aws:iam::123456789012:role/apierror",
                                "session_name", "cn-north-1", NULL,
                                generator_in_test());
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    aws_provider_destroy(base_provider);
    aws_provider_destroy(provider);
}

TEST_LIST = {
    { "test_random_session_name" , test_random_session_name},
    { "test_sts_uri" , test_sts_uri},
    { "process_sts_response" , test_process_sts_response},
    { "eks_credential_provider" , test_eks_provider},
    { "eks_credential_provider_random_session_name" ,
      test_eks_provider_random_session_name},
    { "eks_credential_provider_api_error" , test_eks_provider_api_error},
    { "sts_credential_provider" , test_sts_provider},
    { "sts_credential_provider_api_error" , test_sts_provider_api_error},
    { 0 }
};
