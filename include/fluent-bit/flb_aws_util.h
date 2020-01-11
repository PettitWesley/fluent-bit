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

#ifdef FLB_HAVE_AWS

#ifndef FLB_AWS_UTIL_H
#define FLB_AWS_UTIL_H

#define AWS_SERVICE_ENDPOINT_FORMAT            "https://%s.%s.amazonaws.com"
#define AWS_SERVICE_ENDPOINT_BASE_LEN          25

#define FLB_AWS_CREDENTIAL_REFRESH_LIMIT       300

#define AWS_IMDS_V2_TOKEN_HEADER               "X-aws-ec2-metadata-token"
#define AWS_IMDS_V2_TOKEN_HEADER_LEN           24

#define AWS_IMDS_V2_TOKEN_TTL_HEADER           "X-aws-ec2-metadata-token-ttl-seconds"
#define AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN       36

#define AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL       "21600"
#define AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN   5

#define AWS_IMDS_V2_TOKEN_TTL                  21600

#define AWS_IMDS_V2_HOST                       "169.254.169.254"
#define AWS_IMDS_V2_TOKEN_PATH                 "/latest/api/token"

/*
 * The AWS HTTP Client is a wrapper around the Fluent Bit's http library.
 * It handles tasks which are common to all AWS API requests (retries,
 * error processing, etc).
 * It is also easily mockable in unit tests.
 */

 struct aws_http_client;

 struct aws_http_header {
     char *key;
     size_t key_len;
     char *val;
     size_t val_len;
 };

typedef int(aws_http_client_request_fn)(struct aws_http_client *aws_client,
                                        int method, const char *uri,
                                        const char *body, size_t body_len,
                                        struct aws_http_header *dynamic_headers,
                                        size_t dynamic_headers_len);

/* TODO: Eventually will need to add a way to call flb_http_buffer_size */

/*
 * Virtual table for aws http client behavior.
 * This makes the client's functionality mockable in unit tests.
 */
struct aws_http_client_vtable {
    aws_http_client_request_fn *request;
};

struct aws_http_client {
    struct aws_http_client_vtable *client_vtable;

    /* Name to identify this client: used in log messages and tests */
    char *name;

    /* Sigv4 */
    int has_auth;
    struct aws_credentials_provider *provider;
    char *region;
    char *service;

    struct flb_upstream *upstream;

    char *host;
    int port;
    char *proxy;
    int flags;

    /*
     * Additional headers which will be added to all requests.
     * The AWS client will add auth headers, content length,
     * and user agent.
     */
     struct aws_http_header *static_headers;
     size_t static_headers_len;

    /*
     * Client from a successful request or the last failed retry.
     * Caller code can use this to access the raw response.
     * Caller code does not need to free this pointer.
     */
    struct flb_http_client *c;

    /*
     * If an API responds with 400, we refresh creds and retry.
     * For safety, credential refresh can only happen once per
     * FLB_AWS_CREDENTIAL_REFRESH_LIMIT.
     */
    time_t refresh_limit;

    /*
     * The parsed AWS API error type returned by the last request.
     * Caller code does not need to free this pointer.
     */
    flb_sds_t error_type;
};

/*
 * Frees the aws_client and the internal flb_http_client.
 * Caller code must free all other memory.
 */
void aws_client_destroy(struct aws_http_client *aws_client);

typedef struct aws_http_client*(aws_http_client_create_fn)();

/*
 * HTTP Client Generator creates a new client structure and sets the vtable.
 * Unit tests can implement a custom generator which returns a mock client.
 * This structure is a virtual table.
 * Client code should not free it.
 */
struct aws_http_client_generator {
    aws_http_client_create_fn *new;
};

/* Get the generator */
struct aws_http_client_generator *generator();

/*
 * Format an AWS regional API endpoint
 */
char *endpoint_for(char* service, char* region);

flb_sds_t parse_error(char *response, size_t response_len);

/*
 * Get an IMDSv2 token
 */
int get_ec2_token(struct aws_http_client *client, flb_sds_t *token,
                  size_t *token_len);

/*
 * Get data from an IMDS path.
 * If token_len > 0, a V2 metadata request is made.
 * If not, a V1 metadata request is made.
 */
int get_metadata(struct aws_http_client *client, char *metadata_path,
                 flb_sds_t *metadata, size_t *metadata_len,
                 flb_sds_t token, size_t token_len);

#endif
#endif /* FLB_HAVE_AWS */
