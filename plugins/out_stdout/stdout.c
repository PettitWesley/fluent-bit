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
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <mbedtls/sha256.h>
#include <msgpack.h>

#include "stdout.h"
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

    // struct flb_aws_provider *provider;
    // struct flb_aws_provider *base_provider;
    //
    // base_provider = flb_aws_env_provider_create();
    // if (!base_provider) {
    //     flb_errno();
    //     return -1;
    // }

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

    struct flb_aws_provider *base_provider;
    struct flb_aws_provider *sts_provider;

    base_provider = flb_aws_env_provider_create();
    if (!base_provider) {
        flb_errno();
        return -1;
    }

    ctx->provider = base_provider;

    // sts_provider = flb_sts_provider_create(config, ctx->tls, base_provider, NULL,
    //                                    "arn:aws:iam::144718711470:role/provider-testing",
    //                                    "session_name", "us-west-2", NULL,
    //                                    flb_aws_client_generator());
    // if (!sts_provider) {
    //     flb_errno();
    //     return -1;
    // }
    //
    // ctx->sts_provider = sts_provider;

    // provider = flb_eks_provider_create(config, ctx->tls, "us-west-2", NULL,
    //                                    flb_aws_client_generator());
    // if (!provider) {
    //     flb_errno();
    //     return -1;
    // }
    //
    // ctx->provider = provider;
    // ctx->provider = flb_aws_env_provider_create();
    // if (!ctx->provider) {
    //     flb_error("[out_s3] Failed to create AWS Credential Provider");
    //     return -1;
    // }
    ctx->u = flb_upstream_create(config, "firenosed-dolphin-bucket.s3.amazonaws.com",
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
    // msgpack_unpacked result;
    // size_t off = 0, cnt = 0;
    struct flb_stdout *ctx = out_context;

    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    int ret;
    size_t b_sent;
    flb_sds_t signature = NULL;
    // char *body = "{\"index\":{\"_index\":\"my_index\",\"_type\":\"my_type\"}}\n"
    //              "{\"@timestamp\":\"2020-01-21T04:34:04.000Z\",\"cpu_p\":0.000000,\"user_p\":0.000000}\n";
    char *body = "Hello S3 (from Fluent Bit!)";
    int len = strlen(body);
    flb_info("len: %d", len);

    // struct flb_aws_credentials *creds;
    //
    // creds = ctx->sts_provider->provider_vtable->get_credentials(ctx->sts_provider);
    // if (!creds) {
    //     flb_errno();
    //     flb_debug("[test] no creds.");
    //     FLB_OUTPUT_RETURN(FLB_OK);
    // }
    //
    // flb_debug("[test] access: %s", creds->access_key_id);
    // flb_debug("[test] secret: %s", creds->secret_access_key);
    // flb_debug("[test] token: %s", creds->session_token);
    //
    // flb_debug("exiting");
    // FLB_OUTPUT_RETURN(FLB_OK);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    char amzdate[50];
    char datestamp[32];
    struct tm *gmt;
    time_t t_now = time(NULL);

    gmt = flb_malloc(sizeof(struct tm));
    if (!gmt) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (!gmtime_r(&t_now, gmt)) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    strftime(amzdate, sizeof(amzdate) - 1, "/from-fluent-bit-%Y%m%dT%H%M%SZ", gmt);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", gmt);
    flb_free(gmt);

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_PUT, amzdate,
                        body, len,
                        "firenosed-dolphin-bucket.s3.amazonaws.com", 443,
                        NULL, 0);

    //flb_http_buffer_size(c, ctx->buffer_size);

    //flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    //flb_http_add_header(c, "Content-Type", 12, "application/x-ndjson", 20);

    ret = flb_http_strip_port_from_host(c);
    if (ret < 0) {
        flb_error("[out_s3] could not sign request with sigv4");
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_debug("[out_s3] Signing request with AWS Sigv4");
    signature = flb_signv4_do(c, FLB_FALSE, FLB_TRUE, time(NULL),
                              "us-east-1", "s3", S3_MODE_SIGNED_PAYLOAD,
                              ctx->provider);
    if (!signature) {
        flb_error("[out_s3] could not sign request with sigv4");
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[out_s3] http_do=%i URI=/_bulk", ret);
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_info("[out_es_test] Wat?? It worked?? ret=%s", ret);
    flb_info("[out_s3] HTTP Status=%i URI=/file.txt", c->resp.status);
    if (c->resp.payload_size > 0) {
        flb_info("[out_s3] HTTP status=%i URI=/_bulk, response:\n%s\n",
                 c->resp.status, c->resp.payload);
    }

    // flb_sds_t json;
    // char *buf = NULL;
    // (void) i_ins;
    // (void) config;
    // //struct flb_time tmp;
    // msgpack_object *p;
    // struct flb_aws_credentials *creds;
    // int i;
    //
    // unsigned char sha256_buf[64] = {0};
    // mbedtls_sha256_context sha256_ctx;
    // flb_sds_t tmp;
    // flb_sds_t cr = flb_sds_create("");
    // char *body_buf = "@cats\"\n/";
    //
    // /* Hashed Payload */
    // mbedtls_sha256_init(&sha256_ctx);
    // mbedtls_sha256_starts(&sha256_ctx, 0);
    // mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) body_buf,
    //                           strlen(body_buf));
    // mbedtls_sha256_finish(&sha256_ctx, sha256_buf);
    //
    // for (i = 0; i < 32; i++) {
    //     tmp = flb_sds_printf(&cr, "%02x", (unsigned char) sha256_buf[i]);
    //     if (!tmp) {
    //         flb_error("[signedv4] error formatting hashed payload");
    //         flb_sds_destroy(cr);
    //         return NULL;
    //     }
    //     cr = tmp;
    // }
    // flb_warn("[test] Hex encoded hash: %s", cr);

    // creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    // if (!creds) {
    //     flb_errno();
    //     flb_debug("[test] no creds.");
    //     FLB_OUTPUT_RETURN(FLB_OK);
    // }

    FLB_OUTPUT_RETURN(FLB_OK);
    return;

    // if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
    //     json = flb_pack_msgpack_to_json_format(data, bytes,
    //                                            ctx->out_format,
    //                                            ctx->json_date_format,
    //                                            ctx->json_date_key);
    //     write(STDOUT_FILENO, json, flb_sds_len(json));
    //     flb_sds_destroy(json);
    //
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
    //
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
