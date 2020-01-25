/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_signv4.h>

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

    ctx->tls = &ins->tls;

    /* Create TLS context */
    ctx->tls->context = flb_tls_context_new(FLB_TRUE,  /* verify */
                                           FLB_TRUE,        /* debug */
                                           NULL,      /* vhost */
                                           NULL,      /* ca_path */
                                           NULL,      /* ca_file */
                                           NULL,      /* crt_file */
                                           NULL,      /* key_file */
                                           NULL);     /* key_passwd */

    ctx->u = flb_upstream_create(config, "vpc-test-domain-ke7thhzoo7jawrhmz6mb7ite7y.us-west-2.es.amazonaws.com",
                                 443, FLB_IO_TLS, ctx->tls);

    /* Export context */
    flb_output_set_context(ins, ctx);

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

    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    int ret;
    size_t b_sent;
    flb_sds_t signature = NULL;
    char *body = "{\"index\":{\"_index\":\"my_index\",\"_type\":\"my_type\"}}\n"
                 "{\"@timestamp\":\"2020-01-21T04:34:04.000Z\",\"cpu_p\":0.000000,\"user_p\":0.000000}\n";
    int len = strlen(body);
    flb_info("len: %d", len);

    char *access = NULL;
    access = getenv("AWS_ACCESS_KEY_ID");
    if (!access) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    char *secret = NULL;
    secret = getenv("AWS_SECRET_ACCESS_KEY");
    if (!secret) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, "/_bulk",
                        NULL, 0, NULL, 0, NULL, 0);

    //flb_http_buffer_size(c, ctx->buffer_size);

    //flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/x-ndjson", 20);

    flb_debug("[out_es] Signing request with AWS Sigv4");
    signature = flb_signv4_do(c, FLB_TRUE, FLB_TRUE, time(NULL),
                              access, "us-west-2", "es",
                              secret, NULL);
    if (!signature) {
        flb_error("[out_es] could not sign request with sigv4");
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[out_es] http_do=%i URI=/_bulk", ret);
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_info("[out_es_test] Wat?? It worked?? ret=%s", ret);
    flb_info("[out_es] HTTP Status=%i URI=/_bulk", c->resp.status);
    if (c->resp.payload_size > 0) {
        flb_info("[out_es] HTTP status=%i URI=/_bulk, response:\n%s\n",
                 c->resp.status, c->resp.payload);
    }

    flb_info("_________")

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
