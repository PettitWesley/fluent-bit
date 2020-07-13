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

#include "stdout.h"

static int cb_s3_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp = NULL;
    struct flb_s3 *ctx = NULL;
    const char *role_arn = NULL;
    const char *external_id = NULL;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_s3));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    tmp = flb_output_get_property("bucket", ins);
    if (tmp) {
        ctx->bucket = tmp;
    } else {
        flb_error("[out_s3] 'bucket' is a required parameter");
        goto error;
    }

    tmp = flb_output_get_property("prefix", ins);
    if (tmp) {
        ctx->prefix = tmp;
    } else {
        flb_error("[out_s3] 'prefix' is a required parameter");
        goto error;
    }

    tmp = flb_output_get_property("region", ins);
    if (tmp) {
        ctx->region = tmp;
    } else {
        flb_error("[out_s3] 'region' is a required parameter");
        goto error;
    }

    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        ctx->time_key = tmp;
    } else {
        flb_error("[out_s3] 'time_key' is a required parameter");
        goto error;
    }

    tmp = flb_output_get_property("endpoint", ins);
    if (tmp) {
        ctx->endpoint = tmp;
        ctx->free_endpoint = FLB_FALSE;
    } else {
        /* default endpoint for the given region */
        ctx->endpoint = flb_aws_endpoint("s3", ctx->region);
        ctx->free_endpoint = FLB_TRUE;
        if (!ctx->endpoint) {
            flb_error("[out_s3] Could not construct S3 endpoint");
            goto error;
        }
    }

    /* AWS provider needs a separate TLS instance */
    ctx->provider_tls.context = flb_tls_context_new(FLB_TRUE,
                                                    ins->tls_debug,
                                                    ins->tls_vhost,
                                                    ins->tls_ca_path,
                                                    ins->tls_ca_file,
                                                    ins->tls_crt_file,
                                                    ins->tls_key_file,
                                                    ins->tls_key_passwd);
    if (!ctx->provider_tls.context) {
        flb_errno();
        goto error;
    }

    ctx->provider = flb_standard_chain_provider_create(config,
                                                       &ctx->provider_tls,
                                                       ctx->aws_region,
                                                       NULL,
                                                       flb_aws_client_generator());

    if (!ctx->provider) {
        flb_error("[out_s3] Failed to create AWS Credential Provider");
        goto error;
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        /* Use the STS Provider */
        ctx->base_provider = ctx->provider;
        role_arn = tmp;
        tmp = flb_output_get_property("external_id", ins);
        if (tmp) {
            external_id = tmp;
        }

        /* STS provider needs yet another separate TLS instance */
        ctx->sts_provider_tls.context = flb_tls_context_new(FLB_TRUE,
                                                            ins->tls_debug,
                                                            ins->tls_vhost,
                                                            ins->tls_ca_path,
                                                            ins->tls_ca_file,
                                                            ins->tls_crt_file,
                                                            ins->tls_key_file,
                                                            ins->tls_key_passwd);

        ctx->provider = flb_sts_provider_create(config,
                                                &ctx->sts_provider_tls,
                                                ctx->base_provider,
                                                external_id,
                                                role_arn,
                                                ctx->session_name,
                                                ctx->region,
                                                NULL,
                                                flb_aws_client_generator());
        if (!ctx->provider) {
            flb_error("[out_s3] Failed to create AWS STS Credential "
                      "Provider");
            goto error;
        }

    }

    /* create S3 client */
    ctx->s3_client = generator->create();
    if (!ctx->s3_client) {
        goto error;
    }
    ctx->s3_client->name = "s3_client";
    ctx->s3_client->has_auth = FLB_TRUE;
    ctx->s3_client->provider = ctx->provider;
    ctx->s3_client->region = ctx->region;
    ctx->s3_client->service = "s3";
    ctx->s3_client->port = 443;
    ctx->s3_client->flags = 0;
    ctx->s3_client->proxy = NULL;
    ctx->s3_client->s3_mode = S3_MODE_SIGNED_PAYLOAD;

    ctx->s3_client->upstream = flb_upstream_create(config, ctx->endpoint, 443,
                                                   FLB_IO_TLS, &ins->tls);
    if (!ctx->s3_client->upstream) {
        flb_error("[out_s3] Connection initialization error");
        goto error;
    }

    ctx->s3_client->host = ctx->endpoint;

    /* initialize credentials in sync mode */
    ctx->provider->provider_vtable->sync(ctx->provider);
    ctx->provider->provider_vtable->init(ctx->provider);
    /* set back to async */
    ctx->provider->provider_vtable->async(ctx->provider);

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;

error:
    s3_conf_destroy(ctx);
    return -1;
}

static void s3_conf_destroy(struct flb_s3 *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->free_endpoint == FLB_TRUE) {
        flb_free(ctx->endpoint);
    }

    if (ctx->base_provider) {
        flb_aws_provider_destroy(ctx->base_provider);
    }

    if (ctx->provider) {
        flb_aws_provider_destroy(ctx->provider);
    }

    if (ctx->provider_tls.context) {
        flb_tls_context_destroy(ctx->provider_tls.context);
    }

    if (ctx->sts_provider_tls.context) {
        flb_tls_context_destroy(ctx->sts_provider_tls.context);
    }

    if (ctx->session_name) {
        flb_free(session_name);
    }

    if (ctx->s3_client) {
        flb_aws_client_destroy(ctx->s3_client);
    }
}

/*
 * The S3 file name is
 * /<prefix>/-<datestamp>
 */
static flb_sds_t construct_uri(struct flb_s3 *ctx)
{
    flb_sds_t uri;
    flb_sds_t tmp;
    char datestamp[40];
    struct tm *gmt;
    time_t t_now = time(NULL);

    if (!gmtime_r(&t_now, gmt)) {
        flb_errno();
        return NULL;
    }

    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%dT%H%M%SZ", gmt);

    uri = flb_sds_create_size(strlen(ctx->prefix) + 50);

    tmp = flb_sds_printf(&uri, "/%/%", ctx->prefix, datestamp);
    if (!tmp) {
        flb_error("[out_s3] Failed to construct request URI");
        flb_sds_destroy(uri);
    }
    uri = tmp;

    return uri;
}

static void cb_s3_flush(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    struct flb_s3 *ctx = out_context;
    flb_sds_t json;
    flb_sds_t uri;
    (void) i_ins;
    (void) config;

    json = flb_pack_msgpack_to_json_format(data, bytes,
                                           FLB_PACK_JSON_FORMAT_LINES,
                                           FLB_PACK_JSON_DATE_ISO8601,
                                           ctx->time_key);

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

static int cb_s3_exit(void *data, struct flb_config *config)
{
    struct flb_stdout *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Plugin registration */
struct flb_output_plugin out_stdout_plugin = {
    .name         = "s3",
    .description  = "Send events to Amazon S3",
    .cb_init      = cb_s3_init,
    .cb_flush     = cb_s3_flush,
    .cb_exit      = cb_s3_exit,
    .flags        = 0,
    .config_map   = config_map
};
