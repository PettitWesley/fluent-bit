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
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#include <msgpack.h>
#include "stdout.h"

static int flush_callback(struct flb_ml_parser *parser,
                          struct flb_ml_stream *mst,
                          void *data, char *buf_data, size_t buf_size)
{
    struct ml_ctx *ctx = data;

    if (ctx->debug_flush) {
        flb_ml_flush_stdout(parser, mst, data, buf_data, buf_size);
    }

    /* Append incoming record to our msgpack context buffer */
    msgpack_sbuffer_write(&ctx->mp_sbuf, buf_data, buf_size);

    return 0;
}

static int multiline_load_parsers(struct flb_stdout *ctx)
{
    int ret;
    struct mk_list *head;
    struct mk_list *head_p;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *val = NULL;
    struct flb_ml_parser_ins *parser_i;

    if (!ctx->multiline_parsers) {
        return -1;
    }

    /*
     * Iterate all 'multiline.parser' entries. Every entry is considered
     * a group which can have multiple multiline parser instances.
     */
    flb_config_map_foreach(head, mv, ctx->multiline_parsers) {
        mk_list_foreach(head_p, mv->val.list) {
            val = mk_list_entry(head_p, struct flb_slist_entry, _head);

            /* Create an instance of the defined parser */
            parser_i = flb_ml_parser_instance_create(ctx->m, val->str);
            if (!parser_i) {
                return -1;
            }

            /* Always override parent parser values */
            if (ctx->key_content) {
                ret = flb_ml_parser_instance_set(parser_i,
                                                 "key_content",
                                                 ctx->key_content);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "could not override 'key_content'");
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int multiline(struct flb_stdout *ctx,
                     const void *data, size_t bytes, const char *tag)
{
    int ret;
    int ok = MSGPACK_UNPACK_SUCCESS;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_time tm;

    /* reset mspgack size content */
    ctx->mp_sbuf.size = 0;

    /* process records */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == ok) {
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        ret = flb_ml_append_object(ctx->m, ctx->stream_id, &tm, obj);
        if (ret != 0) {
            flb_plg_warn(ctx->ins,
                          "could not ingest record from tag into multiline parser: %s", tag);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* flush all pending buffered data */
    flb_ml_flush_pending_now(ctx->m);

    if (ctx->mp_sbuf.size > 0) {
        return 0;
    }

    /* multiline failed to parse any records */
    return -1;
}


static int cb_stdout_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_stdout *ctx = NULL;
    int len;
    uint64_t stream_id;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_stdout));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->debug_flush = FLB_FALSE;

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

    /* Init buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    /* Create multiline context */
    ctx->m = flb_ml_create(config, ctx->ins->name);
    if (!ctx->m) {
        /*
        * we don't free the context since upon init failure, the exit
         * callback will be triggered with our context set above.
         */
        return -1;
    }

    /* Load the parsers/config */
    ret = multiline_load_parsers(ctx);
    if (ret == -1) {
        return -1;
    }

    /* Create a stream for this file */
    len = strlen(ins->name);
    ret = flb_ml_stream_create(ctx->m,
                               ins->name, len,
                               flush_callback, ctx,
                               &stream_id);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not create multiline stream");
        return -1;
    }
    ctx->stream_id = stream_id;

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

#ifdef FLB_HAVE_METRICS
static void print_metrics_text(struct flb_output_instance *ins,
                               const void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    cmt_sds_t text;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != 0) {
        flb_plg_error(ins, "could not process metrics payload");
        return;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);

    /* destroy cmt context */
    cmt_destroy(cmt);

    printf("%s", text);
    fflush(stdout);

    cmt_encode_text_destroy(text);
}
#endif


static void cb_stdout_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_stdout *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;
    const void *final_data = data;
    size_t final_bytes = bytes;
    int ret;

    flb_plg_info(ctx->ins, "flush data size: %zu", bytes);

#ifdef FLB_HAVE_METRICS
    /* Check if the event type is metrics, handle the payload differently */
    if (flb_input_event_type_is_metric(ins)) {
        print_metrics_text(ctx->ins, (char *) data, bytes);
        FLB_OUTPUT_RETURN(FLB_OK);
    }
#endif

    ret = multiline(ctx, data, bytes, tag);

    if (ret == 0) {
        final_data = ctx->mp_sbuf.data;
        final_bytes = ctx->mp_sbuf.size;
    }

    /* Assuming data is a log entry...*/
    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(final_data, final_bytes,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->date_key);
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

        /* Multiline Core Engine based API */
    {
     FLB_CONFIG_MAP_BOOL, "debug_flush", "false",
     0, FLB_TRUE, offsetof(struct ml_ctx, debug_flush),
     "enable debugging for concatenation flush to stdout"
    },

    {
     FLB_CONFIG_MAP_CLIST, "multiline.parser", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct ml_ctx, multiline_parsers),
     "specify one or multiple multiline parsers: docker, cri, go, java, etc."
    },

    {
     FLB_CONFIG_MAP_STR, "multiline.key_content", NULL,
     0, FLB_TRUE, offsetof(struct ml_ctx, key_content),
     "specify the key name that holds the content to process."
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
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
    .config_map   = config_map
};
