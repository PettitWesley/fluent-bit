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
#include <fluent-bit/flb_aws_util.h>

#include <stdlib.h>

static int get_ec2_token(struct flb_upstream *upstream, flb_sds_t *token, unsigned int *token_len)
{
    struct flb_http_client *client;
    size_t b_sent;
    int ret;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_error("[filter_aws] connection initialization error");
        return -1;
    }

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn, FLB_HTTP_PUT,
                             FLB_AWS_IMDS_V2_TOKEN_PATH,
                             NULL, 0, FLB_AWS_IMDS_V2_HOST,
                             80, NULL, 0);

    if (!client) {
        flb_error("[filter_aws] count not create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_add_header(client, FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER,
                        FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN,
                        FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL,
                        FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN);

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_debug("[filter_aws] IMDSv2 token request http_do=%i, HTTP Status: %i",
              ret, client->resp.status);

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_debug("[filter_aws] IMDSv2 token response\n%s",
                      client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    *token = flb_sds_create_len(client->resp.payload,
                                client->resp.payload_size);
    *token_len->imds_v2_token_len = client->resp.payload_size;

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    return 0;
}

static int get_metadata(struct flb_upstream *upstream, char *metadata_path,
                        flb_sds_t *metadata, unsigned int *metadata_len,
                        flb_sds_t token, unsigned int token_len);
{
    struct flb_http_client *client;
    size_t b_sent;
    int ret;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_error("[filter_aws] connection initialization error");
        return -1;
    }

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn,
                             FLB_HTTP_GET, metadata_path,
                             NULL, 0,
                             FLB_FILTER_AWS_IMDS_V2_HOST, 80,
                             NULL, 0);

    if (!client) {
        flb_error("[filter_aws] count not create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN,
                        token,
                        token_len);

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_debug("[filter_aws] IMDSv2 metadata request http_do=%i, HTTP Status: %i",
              ret, client->resp.status);

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_debug("[filter_aws] IMDSv2 metadata request\n%s",
                      client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    *metadata = flb_sds_create_len(client->resp.payload,
                                   client->resp.payload_size);

    if (!metadata) {
        flb_errno();
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    *metadata_len = client->resp.payload_size;

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    return 0;
}
