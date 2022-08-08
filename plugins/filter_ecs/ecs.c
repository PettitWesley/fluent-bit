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
    int ret;
    struct flb_filter_ecs *ctx = NULL;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_kv *kv;
    struct flb_split_entry *sentry;
    int list_size;
    struct flb_ecs_metadata_key *ecs_meta = NULL;
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
    ctx->metadata_keys_len = 0;

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

            ecs_meta = flb_calloc(1, sizeof(struct flb_ecs_metadata_key));
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
            ctx->metadata_keys_len++;
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

    return 0;

error:
    flb_plg_error(ctx->ins, "Initialization failed.");
    flb_free(ctx);
    return -1;
}

/*
 * Both container instance and task ARNs have the ID at the end after last '/'
 */
static flb_sds_t parse_id_from_arn(const char *arn, int len)
{
    int i;
    flb_sds_t ID = NULL;
    int last_slash = 0;

    for (i = 0; i < len; i++) {
        if (arn[i] == '/') {
            last_slash = i;
        }
    }

    if (last_slash == 0 || last_slash >= len - 1) {
        return NULL;
    }

    ID = flb_sds_create_len(arn + last_slash, len - last_slash);
    if (ID == NULL) {
        flb_errno();
        return NULL;
    }

    return ID;
}

/*
 * This deserializes the msgpack metadata buf to msgpack_object
 * which can be used with flb_ra_translate in the main filter callback
 */
static int flb_ecs_metadata_buffer_init(struct flb_filter_ecs *ctx,
                                        struct flb_ecs_metadata_buffer *meta)
{
    msgpack_unpacked result;
    msgpack_object root;
    size_t off = 0;
    int ret;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, meta->buf, meta->size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack flb_ecs_metadata_buffer");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "Cannot unpack flb_ecs_metadata_buffer, msgpack_type=%i",
                      root.type);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    meta->unpacked = result;
    meta->obj = root;

    return 0;
}

static void flb_ecs_metadata_buffer_destroy(struct flb_ecs_metadata_buffer *meta)
{
    if (meta) {
        flb_free(meta->buf);
        msgpack_unpacked_destroy(&meta->unpacked);
        flb_free(meta);
    }
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
    int found_cluster = FLB_FALSE;
    int found_version = FLB_FALSE;
    int found_instance = FLB_FALSE;
    int i;
    char *buffer;
    size_t size;
    size_t b_sent;
    size_t off = 0;
    struct flb_ecs_metadata_buffer *meta_buf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    flb_sds_t container_instance_id = NULL;

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
    flb_http_buffer_size(c, 0); /* 0 means unlimited */

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

    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not parse response from %s; response=\n%s", 
                     FLB_ECS_FILTER_CLUSTER_PATH, c->resp.payload);
        return -1;
    }

     /* release resources */
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    /* parse metadata response */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buffer, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack %s response to find metadata\n%s",
                      FLB_ECS_FILTER_CLUSTER_PATH, c->resp.payload);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "%s response parsing failed, msgpack_type=%i",
                      FLB_ECS_FILTER_CLUSTER_PATH,
                      root.type);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* 
     * We copy the metadata response to a new buffer
     * So we can define the metadata key names and parse ARN values
     */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* 
Metadata Response:
{
    "Cluster": "cluster_name",
    "ContainerInstanceArn": "arn:aws:ecs:region:aws_account_id:container-instance/cluster_name/container_instance_id",
    "Version": "Amazon ECS Agent - v1.30.0 (02ff320c)"
}
We will create:
{
    "ClusterName": "cluster_name",
    "ContainerInstanceArn": "arn:aws:ecs:region:aws_account_id:container-instance/cluster_name/container_instance_id",
    "ContainerInstanceID": "container_instance_id"
    "ECSAgentVersion": "Amazon ECS Agent - v1.30.0 (02ff320c)"
}
    */

    msgpack_pack_map(&tmp_pck, 4);

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "%s response parsing failed, msgpack key type=%i",
                         FLB_ECS_FILTER_CLUSTER_PATH,
                         key.type);
        }

        if (key.via.str.size == 7 && strncmp(key.via.str.ptr, "Cluster", 7) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Cluster' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                return -1;
            }

            found_cluster = FLB_TRUE;
            msgpack_pack_str(&tmp_pck, 11);
            msgpack_pack_str_body(&tmp_pck,
                                  "ClusterName",
                                  11);
            msgpack_pack_str(&tmp_pck, (int) val.via.str.size);
            msgpack_pack_str_body(&tmp_pck,
                                  val.via.str.ptr,
                                  (int) val.via.str.size);
        }
        else if (key.via.str.size == 20 && strncmp(key.via.str.ptr, "ContainerInstanceArn", 20) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'ContainerInstanceArn' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                return -1;
            }

            /* first pack the ARN */
            found_instance = FLB_TRUE;
            msgpack_pack_str(&tmp_pck, 20);
            msgpack_pack_str_body(&tmp_pck,
                                  "ContainerInstanceArn",
                                  20);
            msgpack_pack_str(&tmp_pck, (int) val.via.str.size);
            msgpack_pack_str_body(&tmp_pck,
                                  val.via.str.ptr,
                                  (int) val.via.str.size);
            /* then pack the ID */
            container_instance_id = parse_id_from_arn(val.via.str.ptr,  (int) val.via.str.size);
            if (container_instance_id == NULL) {
                flb_plg_error(ctx->ins, "metadata parsing: failed to get ID from %.*s",
                              (int) val.via.str.size, val.via.str.ptr);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                return -1;
            }
            msgpack_pack_str(&tmp_pck, 19);
            msgpack_pack_str_body(&tmp_pck,
                                  "ContainerInstanceID",
                                  19);
            msgpack_pack_str(&tmp_pck, flb_sds_len(container_instance_id));
            msgpack_pack_str_body(&tmp_pck,
                                  container_instance_id,
                                  flb_sds_len(container_instance_id));
            flb_sds_destroy(container_instance_id);
        } else if (key.via.str.size == 7 && strncmp(key.via.str.ptr, "Version", 7) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Version' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                return -1;
            }

            found_version = FLB_TRUE;
            msgpack_pack_str(&tmp_pck, 15);
            msgpack_pack_str_body(&tmp_pck,
                                  "ECSAgentVersion",
                                  15);
            msgpack_pack_str(&tmp_pck, (int) val.via.str.size);
            msgpack_pack_str_body(&tmp_pck,
                                  val.via.str.ptr,
                                  (int) val.via.str.size);
        }

    }

    flb_free(buffer);
    msgpack_unpacked_destroy(&result);

    if (found_cluster == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Cluster' from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }
    if (found_instance == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'ContainerInstanceArn' from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }
    if (found_version == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Version' from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }

    meta_buf = flb_calloc(1, sizeof(struct flb_ecs_metadata_buffer));
    if (!meta_buf) {
        flb_errno();
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }

    meta_buf->buf = tmp_sbuf.data;
    meta_buf->size = tmp_sbuf.size;

    ret = flb_ecs_metadata_buffer_init(ctx, meta_buf);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not init metadata buffer from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        flb_free(meta_buf);
        return -1;
    }

    ctx->cluster_metadata = meta_buf;
    ctx->has_cluster_metadata = FLB_TRUE;
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
    int len;
    struct flb_time tm;
    int total_records;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ecs_metadata_key *metadata_key;
    flb_sds_t val;

    /* First check that the metadata has been retrieved */
    if (!ctx->has_cluster_metadata) {
        ret = get_ecs_cluster_metadata(ctx);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not retrieve cluster metadata "
                          "from ECS Agent");
            return FLB_FILTER_NOTOUCH;
        }
        //TODO: cluster metadata can be exposed in global env ctx
    }
    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate over each item */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)
           == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map. We 'unpack' each record, and then re-pack
         * it with the new fields added.
         */

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            flb_plg_error(ctx->ins, "cb_filter buffer wrong type, msgpack_type=%i",
                          result.data.type);
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* obj should now be the record map */
        if (obj->type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "Record wrong type, msgpack_type=%i",
                          obj->type);
            continue;
        }

        /* re-pack the array into a new buffer */
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        /* new record map size is old size + the new keys we will add */
        total_records = obj->via.map.size + ctx->metadata_keys_len;
        msgpack_pack_map(&tmp_pck, total_records);

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for(i=0; i < obj->via.map.size; i++) {
            msgpack_pack_object(&tmp_pck, (kv+i)->key);
            msgpack_pack_object(&tmp_pck, (kv+i)->val);
        }

        /* append new keys */
        mk_list_foreach_safe(head, tmp, &ctx->metadata_keys) {
            metadata_key = mk_list_entry(head, struct flb_ecs_metadata_key, _head);
            val = flb_ra_translate(metadata_key->ra, NULL, 0,
                                   ctx->cluster_metadata->obj, NULL);
            if (!val) {
                flb_plg_error(ctx->ins, "Translation failed for %s : %s",
                              metadata_key->key, metadata_key->template);
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                return FLB_FILTER_NOTOUCH;
            }
            len = flb_sds_len(metadata_key->key);
            msgpack_pack_str(&tmp_pck, len);
            msgpack_pack_str_body(&tmp_pck,
                                  metadata_key->key,
                                  len);
            len = flb_sds_len(val);
            msgpack_pack_str(&tmp_pck, len);
            msgpack_pack_str_body(&tmp_pck,
                                  val,
                                  len);
            flb_sds_destroy(val);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

static void flb_filter_ecs_destroy(struct flb_filter_ecs *ctx)
{
    //TODO:
    flb_free(ctx);
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
