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

    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        split = flb_utils_split(kv->val, ' ', 3);
        list_size = mk_list_size(split);

        if (list_size == 0 || list_size > 2) {
            flb_plg_error(ctx->ins, "Invalid config for %s", kv->key);
            flb_free(ctx);
            flb_utils_split_free(split);
            return -1;
        }
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
     "Add a metadata key/value pair with the given key and given value from the given template"
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
