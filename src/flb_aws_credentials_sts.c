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
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

#include <jsmn/jsmn.h>
#include <stdlib.h>
#include <time.h>


/*
 * A provider that uses credentials from the base provider to call STS
 * and assume an IAM Role.
 */
static struct aws_credentials_provider_sts {
    struct aws_credentials_provider *base_provider;

    /* upstream connection to sts */
    struct flb_upstream *upstream;

    /* sts:AssumeRole API arguments */
    char *external_id;
    char *role_arn;
    char *session_name;
    /* Fluent Bit uses regional STS endpoints; this is a best practice. */
    char *region;
};

struct aws_credentials_provider *new_sts_assume_role_provider(struct
                                                              aws_credentials_provider
                                                              base_provider,
                                                              char *external_id,
                                                              char *role_arn,
                                                              char *session_name);

static char *sts_uri(struct aws_credentials_provider_sts *implementation)
{

}

static int sts_assume_role_request(struct aws_credentials_provider_sts
                                   *implementation)
{
    struct flb_http_client *client;
    size_t b_sent;
    int ret;
    struct flb_upstream_conn *u_conn;
    flb_sds_t response;
    size_t response_len;
    time_t expiration;
    struct aws_credentials *creds;

    u_conn = flb_upstream_conn_get(implementation->upstream);
    if (!u_conn) {
        flb_error("[aws_credentials] STS Provider: connection initialization error");
        return -1;
    }

    /* Compose HTTP request */
    client = flb_http_client(u_conn, FLB_HTTP_GET,
                             implementation->path,
                             NULL, 0, implementation->host,
                             80, NULL, 0);

    if (!client) {
        flb_error("[aws_credentials] HTTP Provider: could not initialize request");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    /* Perform request */
    flb_debug("[aws_credentials] HTTP Provider: requesting credentials");
    ret = flb_http_do(client, &b_sent);

    if (ret != 0 || client->resp.status != 200) {
        flb_error("[aws_credentials] credentials request http_do=%i, HTTP Status: %i",
                  ret, client->resp.status);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    response = flb_sds_create_len(client->resp.payload,
                                  client->resp.payload_size);
    if (!response) {
        flb_errno();
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);

    response_len = client->resp.payload_size;

    creds = process_http_credentials_response(response, response_len,
                                              &expiration);

    flb_sds_destroy(response);

    if (!creds) {
        return -1;
    }

    implementation->credentials = creds;
    implementation->cred_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
    return 0;
}
