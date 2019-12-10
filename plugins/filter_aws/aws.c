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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <msgpack.h>

#include <stdlib.h>
#include <errno.h>

#include "aws.h"

static int get_ec2_token(struct flb_filter_aws *ctx, struct flb_upstream_conn *u_conn);
static int get_metadata(struct flb_filter_aws *ctx, struct flb_upstream_conn *u_conn, char *metadata_path, flb_sds_t *metadata, int *metadata_len);

static int cb_aws_init(struct flb_filter_instance *f_ins,
                                struct flb_config *config,
                                void *data)
{
    struct flb_filter_aws *ctx = NULL;
    (void) data;

    flb_debug("[debug_aws] in cb_aws_init");

    /* Create context */
    ctx = flb_malloc(sizeof(struct flb_filter_aws));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    /* initilize all fields */
    ctx->imds_v2_token = NULL;
    ctx->imds_v2_token_len = 0;
    ctx->availability_zone = NULL;
    ctx->availability_zone_len = 0;
    ctx->instance_id = NULL;
    ctx->instance_id_len = 0;

    /* enabled fields */
    ctx->instance_id_include = FLB_TRUE;
    ctx->availability_zone_include = FLB_TRUE;

    ctx->new_keys = 2;

    ctx->metadata_retrieved = FLB_FALSE;

    /* Create a TLS object because it is required when creating a fluent bit http upstream connection.
    TLS is not used to connect to IMDS. */
    //todo I think you can pass NULL for tls
    ctx->tls.context = flb_tls_context_new(FLB_FALSE,
                                           FLB_FALSE,
                                           NULL,
                                           NULL,
                                           NULL,
                                           NULL, NULL, NULL);
    if (!ctx->tls.context) {
        return -1;
    }

    //todo I think you can pass NULL for tls
    ctx->ec2_upstream = flb_upstream_create(config,
                                   FLB_FILTER_AWS_IMDS_V2_HOST,
                                   80,
                                   FLB_IO_TCP,
                                   &ctx->tls);
    if (!ctx->ec2_upstream) {
        flb_error("[filter_aws] connection initialization error");
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

/* Get an IMDSv2 token */
static int get_ec2_token(struct flb_filter_aws *ctx, struct flb_upstream_conn *u_conn)
{
    struct flb_http_client *client;
    size_t b_sent;
    int ret;

    flb_debug("[filter_aws] getting an IMDSv2 token");

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn, FLB_HTTP_PUT,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH,
                        NULL, 0, NULL, 0, NULL, 0);

    if (!client) {
        flb_error("[filter_aws] count not create http client");
        return -1;
    }

    flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN);

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
        return -1;
    }

    ctx->imds_v2_token = flb_sds_create_len(client->resp.payload, client->resp.payload_size);
    ctx->imds_v2_token_len = client->resp.payload_size;

    flb_http_client_destroy(client);
    return 0;
}

static int get_metadata(struct flb_filter_aws *ctx, struct flb_upstream_conn *u_conn, char *metadata_path, flb_sds_t *metadata, int *metadata_len)
{
    struct flb_http_client *client;
    size_t b_sent;
    int ret;

    flb_debug("[filter_aws] requesting %s", metadata_path);

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn, FLB_HTTP_GET,
                        metadata_path,
                        NULL, 0, NULL, 0, NULL, 0);

    if (!client) {
        flb_error("[filter_aws] count not create http client");
        return -1;
    }

    flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN,
                        ctx->imds_v2_token,
                        ctx->imds_v2_token_len);

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
        return -1;
    }

    *metadata = flb_sds_create_len(client->resp.payload, client->resp.payload_size);
    *metadata_len = client->resp.payload_size;

    flb_http_client_destroy(client);
    return 0;
}

/* Makes a call to IMDSv2 to set get the values of all metadata fields.
   It can be called repeatedly if some metadata calls initially do not succeed.
   */
static int get_ec2_metadata(struct flb_filter_aws *ctx)
{
    flb_debug("[debug_aws] in get_ec2_metadata");
    struct flb_upstream_conn *u_conn;
    int ret;

    flb_debug("%p", ctx);
    flb_debug("%p", ctx->ec2_upstream);
    u_conn = flb_upstream_conn_get(ctx->ec2_upstream);
    if (!u_conn) {
        flb_error("[filter_aws] connection initialization error");
        return -1;
    }

    if (!ctx->imds_v2_token) {
        ret = get_ec2_token(ctx, u_conn);

        if (ret < 0) {
            flb_upstream_conn_release(u_conn);
            return -1;
        }
    }

    if (ctx->instance_id_include && !ctx->instance_id) {
        ret = get_metadata(ctx, u_conn, FLB_FILTER_AWS_IMDS_V2_INSTANCE_ID_PATH, &ctx->instance_id, &ctx->instance_id_len);

        if (ret < 0) {
            flb_upstream_conn_release(u_conn);
            return -1;
        }
    }

    if (ctx->availability_zone_include && !ctx->availability_zone) {
        ret = get_metadata(ctx, u_conn, FLB_FILTER_AWS_IMDS_V2_AZ_PATH, &ctx->availability_zone, &ctx->availability_zone_len);

        if (ret < 0) {
            flb_upstream_conn_release(u_conn);
            return -1;
        }
    }

    flb_upstream_conn_release(u_conn);
    ctx->metadata_retrieved = FLB_TRUE;
    return 0;
}

static int cb_aws_filter(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_size,
                              struct flb_filter_instance *f_ins,
                              void *context,
                              struct flb_config *config)
{
    struct flb_filter_aws *ctx = context;
    (void) f_ins;
    (void) config;
    size_t off = 0;
    int i = 0;
    int ret;
    struct flb_time tm;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;

    flb_debug("[debug_aws] in cb_aws_filter");

    /* First check that the metadata has been retrieved */
    if (!ctx->metadata_retrieved) {
        ret = get_ec2_metadata(ctx);
        if (ret < 0) {
            flb_error("[filter_aws] Could not retrieve ec2 metadata from IMDSv2");
            return FLB_FILTER_NOTOUCH;
        }
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate over each item */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Each record is a msgpack array [timestamp, map] of the timestamp and record map.
        We 'unpack' each record, and then re-pack it with the new fields added.
        */

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* obj should now be the record map */
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* re-pack the array into a new buffer */
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        /* new record map size is old size + the new keys we will add */
        int total_records = obj->via.map.size + ctx->new_keys;
        msgpack_pack_map(&tmp_pck, total_records);

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for(i=0; i < obj->via.map.size; i++) {
            msgpack_pack_object(&tmp_pck, (kv+i)->key);
            msgpack_pack_object(&tmp_pck, (kv+i)->val);
        }

        /* append new keys */

        if (ctx->availability_zone_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY, FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->availability_zone_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->availability_zone, ctx->availability_zone_len);
        }

        if (ctx->instance_id_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_INSTANCE_ID_KEY, FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->instance_id_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->instance_id, ctx->instance_id_len);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

static void flb_filter_aws_destroy(struct flb_filter_aws *ctx)
{
    if (ctx->ec2_upstream) {
        flb_upstream_destroy(ctx->ec2_upstream);
    }

    if (ctx->imds_v2_token) {
        flb_free(ctx->imds_v2_token);
    }

    if (ctx->availability_zone) {
        flb_free(ctx->availability_zone);
    }

    if (ctx->instance_id) {
        flb_free(ctx->instance_id);
    }

    #ifdef FLB_HAVE_TLS
        if (ctx->tls.context) {
            flb_tls_context_destroy(ctx->tls.context);
        }
    #endif

    flb_free(ctx);
}

static int cb_aws_exit(void *data, struct flb_config *config)
{
    struct flb_filter_aws *ctx = data;

    if (ctx != NULL) {
        flb_filter_aws_destroy(ctx);
    }
    return 0;
}

struct flb_filter_plugin filter_aws_plugin = {
    .name         = "aws",
    .description  = "inject aws metadata",
    .cb_init      = cb_aws_init,
    .cb_filter    = cb_aws_filter,
    .cb_exit      = cb_aws_exit,
    .flags        = 0
};
