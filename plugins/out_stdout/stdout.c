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
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>
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

    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;

    base_provider = flb_aws_env_provider_create();
    if (!base_provider) {
        flb_errno();
        return -1;
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

    provider = flb_sts_provider_create(config, ctx->tls, base_provider, NULL,
                                       "arn:aws:iam::144718711470:role/provider-testing",
                                       "session_name", "us-west-2", NULL,
                                       flb_aws_client_generator());
    if (!provider) {
        flb_errno();
        return -1;
    }

    ctx->provider = provider;

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
    struct flb_upstream_conn *u_conn = NULL;
    struct flb_upstream *upstream = NULL;
    int ret;
    struct flb_aws_credentials *creds;

    upstream = flb_upstream_create(config, "sts.us-west-2.amazonaws.com", 443,
                                   FLB_IO_TLS, ctx->tls);
    if (!upstream) {
        flb_error("[test] Connection initialization error");
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_error("[test] connection initialization error");
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_OK);
    }
    flb_debug("[yay] connection successful!!");

    /* Compose HTTP request */
    struct flb_http_client *client = flb_http_client(u_conn, FLB_HTTP_GET, "/?Action=AssumeRole&RoleArn=arn:aws:iam::144718711470:role/provider-testing&RoleSessionName=session_name&Version=2011-06-15",
                                    NULL, 0,
                                    "sts.us-west-2.amazonaws.com", 443,
                                    NULL, 0);

    if (!client) {
        flb_error("[aws_client] could not initialize request");
        flb_errno();
        goto sts;
    }

    struct flb_aws_provider *base_provider;

    base_provider = flb_aws_env_provider_create();
    if (!base_provider) {
        flb_errno();
        goto sts;
    }

    flb_sds_t signature = flb_signv4_do(client, FLB_TRUE, FLB_TRUE, time(NULL),
                              "us-west-2", "sts",
                              base_provider);
    if (!signature) {
        flb_error("[aws_client] could not sign request");
        flb_errno();
        goto sts;
    }

    /* Perform request */
    size_t b_sent;
    ret = flb_http_do(client, &b_sent);

    if (ret != 0 || client->resp.status != 200) {
        flb_error("[aws_client] request error: http_do=%i, HTTP Status: %i",
                  ret, client->resp.status);
    }

    if (client->resp.payload_size > 0) {
        /* try to parse the error */
        printf("Raw response from ec2: \n%s\n\n", client->resp.payload);
    }
    flb_debug("[yay] This code successfully can make a request to EC2!");

sts:
//
//     creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
//     if (!creds) {
//         flb_errno();
//         FLB_OUTPUT_RETURN(FLB_OK);
//     }
//
//     flb_debug("[test] access: %s", creds->access_key_id);
//     flb_debug("[test] secret: %s", creds->secret_access_key);
//     flb_debug("[test] token: %s", creds->session_token);

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
