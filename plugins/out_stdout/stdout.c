/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include "stdout.h"

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>

#include <monkey/mk_core.h>
#include <string.h>
#include <unistd.h>

// #define ACCESS_KEY_HTTP "http_akid"
// #define SECRET_KEY_HTTP "http_skid"
// #define TOKEN_HTTP      "http_token"
//
// #define HTTP_CREDENTIALS_RESPONSE "{\n\
//     \"AccessKeyId\": \"http_akid\",\n\
//     \"Expiration\": \"2014-10-24T23:00:23Z\",\n\
//     \"RoleArn\": \"TASK_ROLE_ARN\",\n\
//     \"SecretAccessKey\": \"http_skid\",\n\
//     \"Token\": \"http_token\"\n\
// }"
//
// int request_happy_case(struct aws_http_client *aws_client,
//                       int method, const char *uri)
// {
//     flb_debug("[test-check] %d", method == FLB_HTTP_GET);
//
//     /* create an http client so that we can set the response */
//     aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
//     if (!aws_client->c) {
//         flb_errno();
//         return -1;
//     }
//     mk_list_init(&aws_client->c->headers);
//
//     aws_client->c->resp.status = 200;
//     aws_client->c->resp.payload = HTTP_CREDENTIALS_RESPONSE;
//     aws_client->c->resp.payload_size = strlen(HTTP_CREDENTIALS_RESPONSE);
//     aws_client->error_type = NULL;
//
//     return 0;
// }
//
// int request_error_case(struct aws_http_client *aws_client,
//                        int method, const char *uri)
// {
//     flb_debug("[test-check] %d", method == FLB_HTTP_GET);
//
//     /* create an http client so that we can set the response */
//     aws_client->c = flb_calloc(1, sizeof(struct flb_http_client));
//     if (!aws_client->c) {
//         flb_errno();
//         return -1;
//     }
//     mk_list_init(&aws_client->c->headers);
//
//     aws_client->c->resp.status = 400;
//     aws_client->c->resp.payload = NULL;
//     aws_client->c->resp.payload_size = 0;
//     aws_client->error_type = NULL;
//
//     return 0;
// }
//
// /* test/mock version of the aws_http_client request function */
// int test_http_client_request(struct aws_http_client *aws_client,
//                              int method, const char *uri,
//                              const char *body, size_t body_len,
//                              struct aws_http_header *dynamic_headers,
//                              size_t dynamic_headers_len)
// {
//     /*
//      * route to the correct test case fn using the uri
//      */
//     if (strstr(uri, "happy-case") != NULL) {
//         return request_happy_case(aws_client, method, uri);
//     } else if (strstr(uri, "error-case") != NULL) {
//         return request_error_case(aws_client, method, uri);
//     }
//
//     /* uri should match one of the above conditions */
//     flb_errno();
//     return -1;
//
// }
//
// /* Test/mock aws_http_client */
// static struct aws_http_client_vtable test_vtable = {
//     .request = test_http_client_request,
// };
//
// struct aws_http_client *test_http_client_create()
// {
//     struct aws_http_client *client = flb_calloc(1,
//                                                 sizeof(struct aws_http_client));
//     if (!client) {
//         flb_errno();
//         return NULL;
//     }
//     client->client_vtable = &test_vtable;
//     return client;
// }
//
// /* Generator that returns clients with the test vtable */
// static struct aws_http_client_generator test_generator = {
//     .new = test_http_client_create,
// };
//
// struct aws_http_client_generator *generator_in_test()
// {
//     return &test_generator;
// }
//
// /* http and ecs providers */
// static void test_http_provider()
// {
//     struct aws_credentials_provider *provider;
//     struct aws_credentials *creds;
//     int ret;
//     struct flb_config *config;
//     flb_sds_t host;
//     flb_sds_t path;
//
//     config = flb_malloc(sizeof(struct flb_config));
//     if (!config) {
//         flb_errno();
//         return;
//     }
//
//     host = flb_sds_create("127.0.0.1");
//     path = flb_sds_create("/happy-case");
//
//     provider = new_http_provider(config, host, path,
//                                  generator_in_test());
//
//     if (!provider) {
//         flb_errno();
//         return;
//     }
//
//     /* repeated calls to get credentials should return the same set */
//     creds = provider->provider_vtable->get_credentials(provider);
//     if (!creds) {
//         flb_errno();
//         return;
//     }
//     flb_debug("[test-check] %d", strcmp(ACCESS_KEY_HTTP, creds->access_key_id) == 0);
//     flb_debug("[test-check] %d", strcmp(SECRET_KEY_HTTP, creds->secret_access_key) == 0);
//     flb_debug("[test-check] %d", strcmp(TOKEN_HTTP, creds->session_token) == 0);
//
//     aws_credentials_destroy(creds);
//
//     creds = provider->provider_vtable->get_credentials(provider);
//     if (!creds) {
//         flb_errno();
//         return;
//     }
//     flb_debug("[test-check] %d", strcmp(ACCESS_KEY_HTTP, creds->access_key_id) == 0);
//     flb_debug("[test-check] %d", strcmp(SECRET_KEY_HTTP, creds->secret_access_key) == 0);
//     flb_debug("[test-check] %d", strcmp(TOKEN_HTTP, creds->session_token) == 0);
//
//     aws_credentials_destroy(creds);
//
//     /* refresh should return 0 (success) */
//     ret = provider->provider_vtable->refresh(provider);
//     flb_debug("[test-check] %d", ret == 0);
//
//     aws_provider_destroy(provider);
// }

static int cb_stdout_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_stdout *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_stdout));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_error("[out_stdout] unrecognized 'format' option. "
                      "Using 'msgpack'");
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_error("[out_stdout] invalid json_date_format '%s'. "
                      "Using 'double' type", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    ctx->provider = new_ec2_provider(config, generator());
    if (!ctx->provider) {
        flb_errno();
        return -1;
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_stdout_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_stdout *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) i_ins;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

    struct aws_credentials_provider *provider;
    struct aws_credentials *creds;

    provider = ctx->provider;

    //test_http_provider();
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    flb_info("access: %s", creds->access_key_id);
    flb_info("secret: %s", creds->secret_access_key);
    flb_info("token: %s", creds->session_token);

    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(data, bytes,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->json_date_key);
        write(STDOUT_FILENO, json, flb_sds_len(json));
        flb_sds_destroy(json);

        /*
         * If we are 'not' in json_lines mode, we need to add an extra
         * breakline.
         */
        if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
            printf("\n");
        }
        fflush(stdout);
    }
    else {
        /* A tag might not contain a NULL byte */
        buf = flb_malloc(tag_len + 1);
        if (!buf) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        memcpy(buf, tag, tag_len);
        buf[tag_len] = '\0';
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            printf("[%zd] %s: [", cnt++, buf);
            flb_time_pop_from_msgpack(&tmp, &result, &p);
            printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
            msgpack_object_print(stdout, *p);
            printf("]\n");
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }
    fflush(stdout);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_stdout_exit(void *data, struct flb_config *config)
{
    struct flb_stdout *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout, json_date_key),
     NULL
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .cb_exit      = cb_stdout_exit,
    .flags        = 0,
    .config_map   = config_map
};
