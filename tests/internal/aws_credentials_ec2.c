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

#define ACCESS_KEY_EC2 "ec2_akid"
#define SECRET_KEY_EC2 "ec2_skid"
#define TOKEN_EC2      "ec2_token"

#define EC2_CREDENTIALS_RESPONSE "{\n\
    \"AccessKeyId\": \"ec2_akid\",\n\
    \"Expiration\": \"2014-10-24T23:00:23Z\",\n\
    \"RoleArn\": \"EC2_ROLE_ARN\",\n\
    \"SecretAccessKey\": \"ec2_skid\",\n\
    \"Token\": \"ec2_token\"\n\
}"

#define EC2_TOKEN_RESPONSE     "AQAEAGB5i7Jq-RWC7OFZcjSs3Y5uxo06c5VB1vtYIOyVA=="
#define EC2_ROLE_NAME_RESPONSE "my-role-Ec2InstanceRole-1CBV45ZZHA1E5"

int ec2_token_response(struct aws_http_client *aws_client,
                       int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_PUT);

    /* destroy client from previous request */
    if (aws_client->c) {
        flb_http_client_destroy(aws_client->c);
    }

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = EC2_TOKEN_RESPONSE;
    aws_client->c->resp.payload_size = strlen(EC2_TOKEN_RESPONSE);
    aws_client->error_type = NULL;

    return 0;
}

int ec2_role_name_response(struct aws_http_client *aws_client,
                           int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);

    /* destroy client from previous request */
    if (aws_client->c) {
        flb_http_client_destroy(aws_client->c);
    }

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = EC2_ROLE_NAME_RESPONSE;
    aws_client->c->resp.payload_size = strlen(EC2_ROLE_NAME_RESPONSE);
    aws_client->error_type = NULL;

    return 0;
}

int ec2_credentials_response(struct aws_http_client *aws_client,
                             int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);

    /* destroy client from previous request */
    if (aws_client->c) {
        flb_http_client_destroy(aws_client->c);
    }

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = EC2_CREDENTIALS_RESPONSE;
    aws_client->c->resp.payload_size = strlen(EC2_CREDENTIALS_RESPONSE);
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
    /*
     * route to the correct response fn using the uri
     */
     if (strstr(uri, "latest/api/token") != NULL) {
         return ec2_token_response(aws_client, method, uri);
     } else if (strstr(uri, "latest/meta-data/iam/security-credentials/"
                            "my-role-Ec2InstanceRole-1CBV45ZZHA1E5") != NULL) {
         return ec2_credentials_response(aws_client, method, uri);
     } else if (strstr(uri, "latest/meta-data/iam/security-credentials") != NULL)
     {
         return ec2_role_name_response(aws_client, method, uri);
     }

    /* uri should match one of the above conditions */
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

/* Error case mock - uses a different client and generator than happy case */
int test_http_client_error_case(struct aws_http_client *aws_client,
                                int method, const char *uri,
                                const char *body, size_t body_len,
                                struct aws_http_header *dynamic_headers,
                                size_t dynamic_headers_len)
{
    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 500;
    aws_client->c->resp.payload = "error";
    aws_client->c->resp.payload_size = 5;
    aws_client->error_type = NULL;

    return -1;

}

/* Test/mock aws_http_client */
static struct aws_http_client_vtable error_case_vtable = {
    .request = test_http_client_error_case,
};

struct aws_http_client *test_http_client_create_error_case()
{
    struct aws_http_client *client = flb_calloc(1,
                                                sizeof(struct aws_http_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &error_case_vtable;
    return client;
}

/* Generator that returns clients with the test vtable */
static struct aws_http_client_generator error_case_generator = {
    .new = test_http_client_create_error_case,
};

struct aws_http_client_generator *generator_in_test_error_case()
{
    return &error_case_generator;
}

static void test_ec2_provider()
{
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    struct flb_config *config;

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    provider = new_ec2_provider(config, generator_in_test());

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
    TEST_CHECK(strcmp(ACCESS_KEY_EC2, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_EC2, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_EC2, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY_EC2, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_EC2, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_EC2, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    aws_provider_destroy(provider);
}

static void test_ec2_provider_error_case()
{
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    struct flb_config *config;

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    provider = new_ec2_provider(config, generator_in_test_error_case());

    if (!provider) {
        flb_errno();
        return;
    }

    /* get_credentials will fail */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    aws_provider_destroy(provider);
}

TEST_LIST = {
    { "test_ec2_provider" , test_ec2_provider},
    { "test_ec2_provider_error_case" , test_ec2_provider_error_case},
    { 0 }
};
