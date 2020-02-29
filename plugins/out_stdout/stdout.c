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
#include <stdio.h>

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

    // ctx->provider = new_ec2_provider(config, generator());
    // if (!ctx->provider) {
    //     flb_errno();
    //     flb_error("Failed to initialize provider");
    // }

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

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

/*
 * Returns an SDS string with the JSON representation of obj
 * 'estimate' is used to initialize the SDS buffer
 */
// flb_sds_t msgpack_to_json_sds(const msgpack_object *obj, size_t estimate)
// {
//     int ret;
//     flb_sds_t out_buf;
//     flb_sds_t tmp_buf;
//     //TODO: is there a way to find or better guess the size?
//     size_t out_size = estimate * 1.5;
//
//     out_buf = flb_sds_create_size(out_size);
//     if (!out_buf) {
//         flb_errno();
//         return NULL;
//     }
//
//     while (1) {
//         ret = flb_msgpack_to_json(out_buf, out_size, obj);
//         if (ret <= 0) {
//             tmp_buf = flb_sds_increase(out_buf, new_size - out_size);
//             if (tmp_buf) {
//                 out_buf = tmp_buf;
//                 out_size = out_size + 256;
//             } else {
//                 flb_errno();
//                 flb_error("[aws_pack] Buffer memory alloc failed, skipping record");
//                 flb_sds_destroy(out_buf);
//                 return NULL;
//             }
//         } else {
//             break;
//         }
//     }
//
//     return out_buf;
//

/*
 * Parses all incoming msgpack records to events and stores them in the ctx
 * events pointer. Uses the ctx tmp_buf to store the JSON strings.
 *
 * Return value is number of bytes written, or -1 on error.
 */
int msg_pack_to_events(struct flb_stdout *ctx, const char *data, size_t bytes)
{
    size_t off = 0;
    size_t size;
    int i = 0;
    size_t tmp_buf_offset = 0;
    size_t written;
    size_t map_size;
    int ret;
    char *tmp_buf_ptr = NULL;
    struct flb_time tms;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object  map;
    msgpack_object root;
    struct event *event;

    /*
     * Check if tmp_buf is big enough.
     * Realistically, msgpack is never less than half the size of JSON
     * We allocate 3 times as much memory (plus a small constant)
     * just to be super safe.
     * Re-allocs are extremely expensive, having a bit of extra memory is not.
     */
    size = 3 * bytes + 100;
    if (ctx->tmp_buf == NULL) {
        flb_trace("Increasing tmp_buf to %zu", size);
        ctx->tmp_buf = flb_malloc(sizeof(char) * size);
        if (!ctx->tmp_buf) {
            flb_errno();
            return -1;
        }
        ctx->tmp_buf_size = (3 * bytes + 100);
    }
    else if (ctx->tmp_buf_size < size) {
        flb_trace("Increasing tmp_buf to %zu", size);
        flb_free(ctx->tmp_buf);
        ctx->tmp_buf = flb_malloc(sizeof(char) * size);
        if (!ctx->tmp_buf) {
            flb_errno();
            return -1;
        }
        ctx->tmp_buf_size = size;
    }

    /* initialize events if needed */
    if (ctx->events == NULL) {
        ctx->events = flb_malloc(sizeof(struct event) * 1000);
        if (!ctx->events) {
            flb_errno();
            return -1;
        }
        ctx->events_size = 1000;
    }

    /* unpack msgpack */

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map.
         */
         root = result.data;
         if (root.via.array.size != 2) {
             continue;
         }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* Get the record/map */
        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* re-alloc event buffer if needed */
        if (i > ctx->events_size) {
            size = ctx->events_size * 1.5;
            flb_trace("Increasing event buffer to %zu", size);
            ctx->events = flb_realloc(ctx->events, size);
            if (!ctx->events) {
                flb_errno();
                goto error;
            }
            ctx->events_size = size;
        }

        /* lack of space during iteration is unlikely; but check to be safe */
        size = tmp_buf_offset + 3 * map_size;
        if (size > ctx->tmp_buf_size) {
            flb_trace("In loop re-allocation of tmp_buf to %zu", size);
            ctx->tmp_buf = flb_realloc(ctx->tmp_buf, size);
            if (!ctx->tmp_buf) {
                flb_errno();
                goto error;
            }
            ctx->tmp_buf_size = size;
        }

        /* set tmp_buf_ptr before using it */
        tmp_buf_ptr = ctx->tmp_buf + tmp_buf_offset;
        written = flb_msgpack_to_json(tmp_buf_ptr,
                                      ctx->tmp_buf_size - tmp_buf_offset,
                                      &map);
        if (written < 0) {
            flb_error("Failed to convert msgpack record to JSON");
            goto error;
        }
        tmp_buf_offset += written;
        event = ctx->events + i;
        event->json = tmp_buf_ptr;
        event->len = written;
        event->timestamp = (unsigned long long) (tms.tm.tv_sec * 1000 +
                                                 tms.tm.tv_nsec/1000000);

        i++;
    }
    msgpack_unpacked_destroy(&result);

    // for debug; todo: Remove
    ctx->tmp_buf[tmp_buf_offset] = '\0';
    flb_debug("tmp_buf: %s", ctx->tmp_buf);

    for (int l=0; l < ctx->events_size; l++) {
        event = ctx->events[l];
        flb_debug("event %d: %llu, %10s", l, event->timestamp, event->json);
    }

    return tmp_buf_offset;

error:
    msgpack_unpacked_destroy(&result);
    return -1;
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

    msg_pack_to_events(ctx, data, bytes);

    // struct aws_credentials *creds;
    //
    // creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    // if (!creds) {
    //     flb_info("[result] No creds");
    // } else {
    //     flb_info("[result] Creds!!");
    //     flb_info("[creds] access: %s", creds->access_key_id);
    //     flb_info("[creds] secret: %s", creds->secret_access_key);
    //     flb_info("[creds] token len: %d", flb_sds_len(creds->session_token));
    //     flb_info("[creds] token: %s", creds->session_token);
    //     // for (int i=0; i < flb_sds_len(creds->session_token); i++) {
    //     //     printf("%c", creds->session_token[i]);
    //     // }
    //     // printf("\n");
    // }



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
