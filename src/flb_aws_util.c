/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_aws_credentials.h>

#include <jsmn/jsmn.h>
#include <stdlib.h>

int request_do(struct flb_aws_client *aws_client,
               int method, const char *uri,
               const char *body, size_t body_len,
               struct flb_aws_header *dynamic_headers,
               size_t dynamic_headers_len);

/*
 * https://service.region.amazonaws.com(.cn)
 */
char *flb_aws_endpoint(char* service, char* region)
{
    char *endpoint = NULL;
    size_t len = AWS_SERVICE_ENDPOINT_BASE_LEN;
    int is_cn = FLB_FALSE;


    /* In the China regions, ".cn" is appended to the URL */
    if (strcmp("cn-north-1", region) == 0) {
        len += 3;
        is_cn = FLB_TRUE;
    }
    if (strcmp("cn-northwest-1", region) == 0) {
        len += 3;
        is_cn = FLB_TRUE;
    }
    flb_debug("[remove] len: %d", len);
    len += strlen(service);
    flb_debug("[remove] len: %d", len);
    len += strlen(region);
    flb_debug("[remove] len: %d", len);
    endpoint = flb_malloc(sizeof(char) * (len + 1));
    if (!endpoint) {
        flb_errno();
        return NULL;
    }

    snprintf(endpoint, len, AWS_SERVICE_ENDPOINT_FORMAT, service, region);
    flb_debug("[remove] endpoint: %s", endpoint);

    if (is_cn) {
        strncat(endpoint, ".cn", 3);
    }

    return endpoint;

}

int flb_aws_client_request(struct flb_aws_client *aws_client,
                            int method, const char *uri,
                            const char *body, size_t body_len,
                            struct flb_aws_header *dynamic_headers,
                            size_t dynamic_headers_len)
{
    int ret;

    //TODO: Need to think more about the retry strategy.

    ret = request_do(aws_client, method, uri, body, body_len,
                     dynamic_headers, dynamic_headers_len);

    if (ret == 0 && aws_client->c->resp.status == 200) {
        return 0;
    }

    /*
     * 400 or 403 could indicate an issue with credentials- so we force a
     * refresh on the provider. For safety a refresh can be performed only once
     * per FLB_AWS_CREDENTIAL_REFRESH_LIMIT.
     */
    if (ret == 0 && (aws_client->c->resp.status == 400 ||
        aws_client->c->resp.status == 403)) {
        if (aws_client->has_auth && time(NULL) > aws_client->refresh_limit) {
            aws_client->refresh_limit = time(NULL)
                                        + FLB_AWS_CREDENTIAL_REFRESH_LIMIT;
            aws_client->provider->provider_vtable->refresh(aws_client->provider);
        }
    }

    /* perform a single retry */
    return request_do(aws_client, method, uri, body, body_len,
                      dynamic_headers, dynamic_headers_len);
}

static struct flb_aws_client_vtable client_vtable = {
    .request = flb_aws_client_request,
};

struct flb_aws_client *flb_aws_client_create()
{
    struct flb_aws_client *client = flb_calloc(1,
                                                sizeof(struct flb_aws_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &client_vtable;
    return client;
}

/* Generator that returns clients with the default vtable */

static struct flb_aws_client_generator default_generator = {
    .create = flb_aws_client_create,
};

struct flb_aws_client_generator *flb_aws_client_generator()
{
    return &default_generator;
}

void flb_aws_client_destroy(struct flb_aws_client *aws_client)
{
    if (aws_client) {
        if (aws_client->c) {
            flb_http_client_destroy(aws_client->c);
        }
        if (aws_client->error_type) {
            flb_sds_destroy(aws_client->error_type);
        }
        if (aws_client->upstream) {
            flb_upstream_destroy(aws_client->upstream);
        }
        flb_free(aws_client);
    }
}

int request_do(struct flb_aws_client *aws_client,
                int method, const char *uri,
                const char *body, size_t body_len,
                struct flb_aws_header *dynamic_headers,
                size_t dynamic_headers_len)
{
    size_t b_sent;
    int ret;
    struct flb_upstream_conn *u_conn = NULL;
    flb_sds_t signature = NULL;
    int i;
    struct flb_aws_header header;

    if (aws_client->error_type) {
        /* clear last error */
        flb_sds_destroy(aws_client->error_type);
        aws_client->error_type = NULL;
    }

    if (aws_client->c) {
        /* free leftover client from previous request */
        flb_http_client_destroy(aws_client->c);
        aws_client->c = NULL;
    }

    u_conn = flb_upstream_conn_get(aws_client->upstream);
    if (!u_conn) {
        flb_error("[aws_client] connection initialization error");
        return -1;
    }

    /* Compose HTTP request */
    aws_client->c = flb_http_client(u_conn, method, uri,
                                    body, body_len,
                                    aws_client->host, aws_client->port,
                                    aws_client->proxy, aws_client->flags);

    if (!aws_client->c) {
        flb_error("[aws_client] could not initialize request");
        goto error;
    }

    /* add headers */
    for (i = 0; i < aws_client->static_headers_len; i++) {
        header = aws_client->static_headers[i];
        ret =  flb_http_add_header(aws_client->c,
                                   header.key, header.key_len,
                                   header.val, header.val_len);
        if (ret < 0) {
            flb_error("[aws_client] failed to add header to request");
            goto error;
        }
    }

    for (i = 0; i < dynamic_headers_len; i++) {
        header = dynamic_headers[i];
        ret =  flb_http_add_header(aws_client->c,
                                   header.key, header.key_len,
                                   header.val, header.val_len);
        if (ret < 0) {
            flb_error("[aws_client] failed to add header to request");
            goto error;
        }
    }

    if (aws_client->has_auth) {
        signature = flb_signv4_do(aws_client->c, FLB_TRUE, FLB_TRUE, time(NULL),
                                  aws_client->region, aws_client->service,
                                  aws_client->provider);
        if (!signature) {
            flb_error("[aws_client] could not sign request");
            goto error;
        }
    }

    /* Perform request */
    ret = flb_http_do(aws_client->c, &b_sent);

    if (ret != 0 || aws_client->c->resp.status != 200) {
        flb_error("[aws_client] request error: http_do=%i, HTTP Status: %i",
                  ret, aws_client->c->resp.status);
        if (aws_client->c->resp.payload_size > 0) {
            /* try to parse the error */
            aws_client->error_type = flb_aws_error(aws_client->c->resp.payload,
                                                 aws_client->c->
                                                 resp.payload_size);
        }
        goto error;
    }

    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(signature);
    return 0;

error:
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    if (signature) {
        flb_sds_destroy(signature);
    }
    return -1;
}

/* parses AWS API error responses and returns the value of the __type field */
flb_sds_t flb_aws_error(char *response, size_t response_len) {
    jsmntok_t *tokens = NULL;
    const jsmntok_t *t = NULL;
    char *current_token = NULL;
    jsmn_parser parser;
    int tokens_size = 10;
    size_t size;
    int ret;
    int i = 0;
    int len;
    flb_sds_t error_type = NULL;

    jsmn_init(&parser);

    size = sizeof(jsmntok_t) * tokens_size;
    tokens = flb_calloc(1, size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    ret = jsmn_parse(&parser, response, response_len,
                     tokens, tokens_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_free(tokens);
        flb_debug("[aws_client] Unable to parse API response- response is not"
                  "not valid JSON.");
        return NULL;
    }

    /* return value is number of tokens parsed */
    tokens_size = ret;

    /*
     * jsmn will create an array of tokens like:
     * key, value, key, value
     */
    while (i < (tokens_size - 1)) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type == JSMN_STRING) {
            current_token = &response[t->start];

            if (strncmp(current_token, "__type", 6) == 0) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                error_type = flb_sds_create_len(current_token, len);
                if (!error_type) {
                    flb_errno();
                    flb_free(tokens);
                    return NULL;
                }
                break;
            }
        }

        i++;
    }
    flb_free(tokens);
    return error_type;
}
