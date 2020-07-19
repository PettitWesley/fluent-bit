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
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_output_plugin.h>
#include <msgpack.h>

#include "s3.h"

static void s3_conf_destroy(struct flb_s3 *ctx);

static int cb_s3_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    const char *tmp = NULL;
    struct flb_s3 *ctx = NULL;
    char *role_arn = NULL;
    char *external_id = NULL;
    struct flb_aws_client_generator *generator;
    char *session_name;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_s3));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;

    tmp = flb_output_get_property("bucket", ins);
    if (tmp) {
        ctx->bucket = (char *) tmp;
    } else {
        flb_error("[out_s3] 'bucket' is a required parameter");
        goto error;
    }

    tmp = flb_output_get_property("prefix", ins);
    if (tmp) {
        ctx->prefix = (char *) tmp;
    } else {
        ctx->prefix = "fluent-bit";
    }

    tmp = flb_output_get_property("region", ins);
    if (tmp) {
        ctx->region = (char *) tmp;
    } else {
        flb_error("[out_s3] 'region' is a required parameter");
        goto error;
    }

    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        ctx->time_key = (char *) tmp;
    } else {
        ctx->time_key = "time";
    }

    tmp = flb_output_get_property("endpoint", ins);
    if (tmp) {
        ctx->endpoint = (char *) tmp;
        ctx->free_endpoint = FLB_FALSE;
    } else {
        /* default endpoint for the given region */
        ctx->endpoint = flb_s3_endpoint(ctx->bucket, ctx->region);
        ctx->free_endpoint = FLB_TRUE;
        if (!ctx->endpoint) {
            flb_error("[out_s3] Could not construct S3 endpoint");
            goto error;
        }
    }

    ctx->client_tls.context = flb_tls_context_new(FLB_TRUE,
                                                  ins->tls_debug,
                                                  ins->tls_vhost,
                                                  ins->tls_ca_path,
                                                  ins->tls_ca_file,
                                                  ins->tls_crt_file,
                                                  ins->tls_key_file,
                                                  ins->tls_key_passwd);
    if (!ctx->client_tls.context) {
        flb_plg_error(ctx->ins, "Failed to create tls context");
        goto error;
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
                                                       ctx->region,
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
        role_arn = (char *) tmp;
        tmp = flb_output_get_property("external_id", ins);
        if (tmp) {
            external_id = (char *) tmp;
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

        if (!ctx->sts_provider_tls.context) {
            flb_errno();
            goto error;
        }

        session_name = flb_sts_session_name();
        if (!session_name) {
            flb_error("[out_s3] Failed to create aws iam role "
                      "session name");
            flb_errno();
            goto error;
        }

        ctx->provider = flb_sts_provider_create(config,
                                                &ctx->sts_provider_tls,
                                                ctx->base_provider,
                                                external_id,
                                                role_arn,
                                                session_name,
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
    generator = flb_aws_client_generator();
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
                                                   FLB_IO_TLS, &ctx->client_tls);
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

    if (ctx->client_tls.context) {
        flb_tls_context_destroy(ctx->client_tls.context);
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
    struct tm gmt;
    time_t t_now = time(NULL);

    if (!gmtime_r(&t_now, &gmt)) {
        flb_errno();
        return NULL;
    }

    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%dT%H%M%SZ", &gmt);

    uri = flb_sds_create_size(strlen(ctx->prefix) + 50);

    tmp = flb_sds_printf(&uri, "/%s/%s", ctx->prefix, datestamp);
    if (!tmp) {
        flb_sds_destroy(uri);
        return NULL;
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
    flb_sds_t json = NULL;
    flb_sds_t uri = NULL;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    (void) i_ins;
    (void) config;

    // json = flb_pack_msgpack_to_json_format(data, bytes,
    //                                        FLB_PACK_JSON_FORMAT_LINES,
    //                                        FLB_PACK_JSON_DATE_ISO8601,
    //                                        ctx->time_key);
    json = flb_pack_msgpack_to_json_format(data, bytes,
                                           FLB_PACK_JSON_FORMAT_LINES,
                                           FLB_PACK_JSON_DATE_ISO8601,
                                           "time");
    if (json == NULL) {
        flb_error("[out_s3] Could not create body");
        FLB_OUTPUT_RETURN(FLB_ERROR);

    }
    flb_debug("body is: %s", json);

    uri = construct_uri(ctx);
    if (!uri) {
        flb_error("[out_s3] Failed to construct request URI");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    s3_client = ctx->s3_client;
    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                          uri, json, flb_sds_len(json),
                                          NULL, 0);

    flb_sds_destroy(json);
    flb_sds_destroy(uri);
    if (c) {
        flb_plg_debug(ctx->ins, "PutObject http status=%d", c->resp.status);
        //flb_plg_debug(ctx->ins, "%s", c->resp.payload);
        //flb_plg_debug(ctx->ins, "%d", c->resp.content_length);
        //flb_plg_debug(ctx->ins, "%s", c->resp.headers_end);
        //flb_plg_debug(ctx->ins, "%s", c->resp.data);
    } else {
        flb_plg_error(ctx->ins, "PutOjbect request failed");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_s3_exit(void *data, struct flb_config *config)
{
    struct flb_s3 *ctx = data;

    if (!ctx) {
        return 0;
    }

    s3_conf_destroy(ctx);
    flb_free(ctx);
    return 0;
}

/* Plugin registration */
struct flb_output_plugin out_s3_plugin = {
    .name         = "s3",
    .description  = "Send events to Amazon S3",
    .cb_init      = cb_s3_init,
    .cb_flush     = cb_s3_flush,
    .cb_exit      = cb_s3_exit,
    .flags        = 0,
};
