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

#define ACCESS_KEY_HTTP "http_akid"
#define SECRET_KEY_HTTP "http_skid"
#define TOKEN_HTTP      "http_token"

#define HTTP_CREDENTIALS_RESPONSE "{\n\
    \"AccessKeyId\": \"http_akid\",\n\
    \"Expiration\": \"2014-10-24T23:00:23Z\",\n\
    \"RoleArn\": \"TASK_ROLE_ARN\",\n\
    \"SecretAccessKey\": \"http_skid\",\n\
    \"Token\": \"http_token\"\n\
}"

int request_happy_case(struct aws_http_client *aws_client,
                      int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);

    /* create an http client so that we can set the response */
    aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!aws_client->c) {
        flb_errno();
        return -1;
    }
    mk_list_init(&aws_client->c->headers);

    aws_client->c->resp.status = 200;
    aws_client->c->resp.payload = HTTP_CREDENTIALS_RESPONSE;
    aws_client->c->resp.payload_size = strlen(HTTP_CREDENTIALS_RESPONSE);
    aws_client->error_type = NULL;

    return 0;
}

int request_error_case(struct aws_http_client *aws_client,
                       int method, const char *uri)
{
    TEST_CHECK(method == FLB_HTTP_GET);

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
    /*
     * route to the correct test case fn using the uri
     */
    if (strstr(uri, "happy-case") != NULL) {
        return request_happy_case(aws_client, method, uri);
    } else if (strstr(uri, "error-case") != NULL) {
        return request_error_case(aws_client, method, uri);
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

/* http and ecs providers */
static void test_http_provider()
{
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    struct flb_config *config;
    flb_sds_t host;
    flb_sds_t path;

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    host = flb_sds_create("127.0.0.1");
    path = flb_sds_create("/happy-case");

    provider = new_http_provider(config, host, path,
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
    TEST_CHECK(strcmp(ACCESS_KEY_HTTP, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_HTTP, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_HTTP, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY_HTTP, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_HTTP, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_HTTP, creds->session_token) == 0);

    aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    flb_sds_destroy(path);
    flb_sds_destroy(host);
    aws_provider_destroy(provider);
}

static void test_http_provider_error_case()
{
    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;
    int ret;
    struct flb_config *config;
    flb_sds_t host;
    flb_sds_t path;

    config = flb_malloc(sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    host = flb_sds_create("127.0.0.1");
    path = flb_sds_create("/error-case");

    provider = new_http_provider(config, host, path,
                                 generator_in_test());

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

    flb_sds_destroy(path);
    flb_sds_destroy(host);
    aws_provider_destroy(provider);
}

TEST_LIST = {
    { "test_http_provider" , test_http_provider},
    { "test_http_provider_error_case" , test_http_provider_error_case},
    { 0 }
};
