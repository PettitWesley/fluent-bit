/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_env.h>

#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>
#include <stdlib.h>
#include <errno.h>

#include "ecs.h"

static int cb_ecs_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    int use_v2;
    int ret;
    struct flb_filter_ecs *ctx = NULL;
    const char *tmp = NULL;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_kv *kv;
    struct flb_split_entry *sentry;
    int list_size;
    struct flb_ecs_metadata *ecs_meta = NULL;
    (void) data;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_ecs));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = f_ins;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    mk_list_init(&ctx->metadata_keys);

    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        split = flb_utils_split(kv->val, ' ', 2);
        list_size = mk_list_size(split);

        if (list_size == 0 || list_size > 2) {
            flb_plg_error(ctx->ins, "Invalid config for %s", kv->key);
            flb_utils_split_free(split);
            goto error;
        } else if (strcasecmp(kv->key, "add") == 0) {
            sentry = mk_list_entry_first(split, struct flb_split_entry, _head);

            ecs_meta = flb_calloc(1, sizeof(struct flb_ecs_metadata));
            if (!ecs_meta) {
                flb_errno();
                flb_utils_split_free(split);
                goto error;
            }

            ecs_meta->key = flb_sds_create_len(sentry->value, sentry->len);
            if (!ecs_meta->key) {
                flb_errno();
                flb_utils_split_free(split);
                goto error;
            }

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            ecs_meta->template = flb_sds_create_len(sentry->value, sentry->len);
            if (!ecs_meta->template) {
                flb_errno();
                flb_utils_split_free(split);
                goto error;
            }

            ecs_meta->ra = flb_ra_create(ecs_meta->template, FLB_FALSE);
            if (ecs_meta->ra == NULL) {
                flb_plg_error(ctx->ins, "Could not parse template for `%s`", ecs_meta->key);
                flb_utils_split_free(split);
                goto error;
            }

            mk_list_add(&ecs_meta->_head, &ctx->metadata_keys);
            flb_utils_split_free(split);
        }
    }

    ctx->ecs_upstream = flb_upstream_create(config,
                                            FLB_ECS_FILTER_HOST,
                                            FLB_ECS_FILTER_PORT,
                                            FLB_IO_TCP,
                                            NULL);

    if (!ctx->ecs_upstream) {
        flb_errno();
        flb_plg_error(ctx->ins, "Could not create upstream connection to ECS Agent");
    }

    /* 
     * Remove async flag from upstream 
     * Filters can not coroutine-yield. 
     */
    ctx->ecs_upstream->flags &= ~(FLB_IO_ASYNC);

    ctx->has_cluster_metadata = FLB_FALSE;

error:
    flb_plg_error(ctx->ins, "Initialization failed.");
    flb_free(ctx);
    return -1;
}

/*
 * Get cluster and container instance info, which are static and never change
 */
static int get_ecs_cluster_metadata(struct flb_filter_ecs *ctx)
{
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;
    int ret;
    int root_type;
    char *buffer;
    size_t size;
    size_t b_sent;
    struct flb_ecs_metadata_buffer *meta_buf;

    u_conn = flb_upstream_conn_get(ctx->ecs_upstream);

    if (!u_conn) {
        flb_plg_error(ctx->ins, "ECS agent introspection endpoint connection error");
        return -1;
    }
    
    /* Compose HTTP Client request*/
    c = flb_http_client(u_conn, FLB_HTTP_GET,
                        FLB_ECS_FILTER_CLUSTER_PATH,
                        NULL, 0, 
                        FLB_ECS_FILTER_HOST, FLB_ECS_FILTER_PORT,
                        NULL, 0);
    flb_http_buffer_size(c, ctx->buffer_size);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    ret = flb_http_do(c, &b_sent);
    flb_plg_debug(ctx->ins, "http_do=%i, "
                  "HTTP Status: %i",
                  ret, c->resp.status);

    if (ret != 0 || c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_plg_warn(ctx->ins, "Failed to get metadata from %s, will retry", 
                         FLB_ECS_FILTER_CLUSTER_PATH);
            flb_plg_debug(ctx->ins, "HTTP response\n%s",
                          c->resp.payload);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &buffer, &size, &root_type);

    /* release resources */
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not parse response from %s; response=\n%s", 
                     FLB_ECS_FILTER_CLUSTER_PATH, c->resp.payload);
        return -1;
    }

    /* parse metadata response */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack response to find error\n%s",
                      c->resp.payload);
        return FLB_TRUE;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected payload type=%i",
                      root.type);
        check = FLB_TRUE;
        goto done;
    }


    meta_buf = flb_calloc(1, sizeof(struct flb_ecs_metadata_buffer));
    if (!meta_buf) {
        flb_errno();
        flb_free(buffer);
        return -1;
    }

    // meta_buf->buf = buffer;
    // meta_buf->size = size;

    return 0;
}

static int cb_ecs_filter(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         void **out_buf, size_t *out_size,
                         struct flb_filter_instance *f_ins,
                         struct flb_input_instance *i_ins,
                         void *context,
                         struct flb_config *config)
{
    struct flb_filter_ecs *ctx = context;
    (void) f_ins;
    (void) i_ins;
    (void) config;
    size_t off = 0;
    int i = 0;
    int ret;
    struct flb_time tm;
    int total_records;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;


}

static int cb_ecs_exit(void *data, struct flb_config *config)
{
    struct flb_filter_ecs *ctx = data;

    if (ctx != NULL) {
        flb_filter_ecs_destroy(ctx);
    }
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {

    {
     FLB_CONFIG_MAP_STR, "Add", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Add a metadata key/value pair with the given key and given value from the given template. "
     "Format is `Add KEY TEMPLATE`."
    },

    {0}
};

struct flb_filter_plugin filter_ecs_plugin = {
    .name         = "ecs",
    .description  = "Add AWS ECS Metadata",
    .cb_init      = cb_ecs_init,
    .cb_filter    = cb_ecs_filter,
    .cb_exit      = cb_ecs_exit,
    .config_map   = config_map,
    .flags        = 0
};
