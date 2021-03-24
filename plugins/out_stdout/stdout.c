/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include <msgpack.h>

#include "stdout.h"

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
    ctx->ins = ins;

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
            flb_plg_error(ctx->ins, "unrecognized 'format' option. "
                          "Using 'msgpack'");
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
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

static int process_pack(struct flb_stdout *ctx, flb_sds_t tag, char *buf, size_t size)
{
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_unpacked result;
    struct flb_time tm;
    msgpack_object  *obj;

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            flb_plg_warn(ctx->ins, "processing opening array: %i",
                         result.data.type);
        }
        flb_plg_info(ctx->ins, "found msgpack type: %i", result.data.type);

        obj = &result.data;

        obj->via.map.size

        flb_plg_info(ctx->ins, "array size: %d", obj->via.map.size);

        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        /* Pack record with timestamp */
        msgpack_pack_array(&mp_pck, 2);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);
        msgpack_pack_object(&mp_pck, result.data); /* Ingest real record into the engine */

        flb_info("record: %.*s", mp_sbuf.size, mp_sbuf.data);

        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    flb_plg_warn(ctx->ins, "done processing pack");

    return 0;
}

static ssize_t parse_payload_json(struct flb_stdout *ctx, flb_sds_t tag,
                                  char *payload, size_t size)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    process_pack(ctx, tag, pack, out_size);
    flb_free(pack);

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

    char *str = "[{\"time\": \"2020-11-12T00:30:48.883Z\", \"type\": \"platform.start\", \"record\": {\"requestId\": \"49ae0e5f-bc60-4521-81e3-6e41d6bcb55c\", \"version\": \"$LATEST\"}}, {\"time\": \"2020-11-12T00:30:48.993Z\", \"type\": \"platform.logsSubscription\", \"record\": {\"name\": \"logs_api_http_extension.py\", \"state\": \"Subscribed\", \"types\": [\"platform\", \"function\"]}}, {\"time\": \"2020-11-12T00:30:48.993Z\", \"type\": \"platform.extension\", \"record\": {\"name\": \"logs_api_http_extension.py\", \"state\": \"Ready\", \"events\": [\"INVOKE\", \"SHUTDOWN\"]}}, {\"time\": \"2020-11-12T00:30:49.017Z\", \"type\": \"platform.end\", \"record\": {\"requestId\": \"49ae0e5f-bc60-4521-81e3-6e41d6bcb55c\"}}, {\"time\": \"2020-11-12T00:30:49.017Z\", \"type\": \"platform.report\", \"record\": {\"requestId\": \"49ae0e5f-bc60-4521-81e3-6e41d6bcb55c\", \"metrics\": {\"durationMs\": 15.74, \"billedDurationMs\": 100, \"memorySizeMB\": 128, \"maxMemoryUsedMB\": 62, \"initDurationMs\": 226.3}}}]";

    parse_payload_json(ctx, "tag", str, (size_t) strlen(str));

    FLB_OUTPUT_RETURN(FLB_OK);

    // if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
    //     json = flb_pack_msgpack_to_json_format(data, bytes,
    //                                            ctx->out_format,
    //                                            ctx->json_date_format,
    //                                            ctx->date_key);
    //     write(STDOUT_FILENO, json, flb_sds_len(json));
    //     flb_sds_destroy(json);

    //     /*
    //      * If we are 'not' in json_lines mode, we need to add an extra
    //      * breakline.
    //      */
    //     if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
    //         printf("\n");
    //     }
    //     fflush(stdout);
    // }
    // else {
    //     /* A tag might not contain a NULL byte */
    //     buf = flb_malloc(tag_len + 1);
    //     if (!buf) {
    //         flb_errno();
    //         FLB_OUTPUT_RETURN(FLB_RETRY);
    //     }
    //     memcpy(buf, tag, tag_len);
    //     buf[tag_len] = '\0';
    //     msgpack_unpacked_init(&result);
    //     while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
    //         printf("[%zd] %s: [", cnt++, buf);
    //         flb_time_pop_from_msgpack(&tmp, &result, &p);
    //         printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
    //         msgpack_object_print(stdout, *p);
    //         printf("]\n");
    //     }
    //     msgpack_unpacked_destroy(&result);
    //     flb_free(buf);
    // }
    // fflush(stdout);

    // FLB_OUTPUT_RETURN(FLB_OK);
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
     "Specifies the data format to be printed. Supported formats are msgpack json, json_lines and json_stream."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout, json_date_key),
    "Specifies the format of the date. Supported formats are double, iso8601 and epoch."
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
