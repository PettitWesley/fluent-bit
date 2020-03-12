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
#include <fluent-bit/flb_output_plugin.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>

#include <monkey/mk_core.h>
#include <msgpack.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "cloudwatch_logs.h"
#include "cloudwatch_api.h"

static struct flb_aws_header content_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "application/x-amz-json-1.1",
    .val_len = 26,
};

static int cb_cloudwatch_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    const char *tmp;
    struct flb_cloudwatch *ctx = NULL;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_cloudwatch));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;

    tmp = flb_output_get_property("log_group_name", ins);
    if (tmp) {
        ctx->log_group = tmp;
    } else {
        flb_error("[out_cloudwatch] 'log_group_name' is a required field");
        goto error;
    }

    tmp = flb_output_get_property("log_stream_name", ins);
    if (tmp) {
        ctx->log_stream_name = tmp;
    }

    tmp = flb_output_get_property("log_stream_prefix", ins);
    if (tmp) {
        ctx->log_stream_prefix = tmp;
    }

    if (!ctx->log_stream_name && !ctx->log_stream_prefix) {
        flb_error("[out_cloudwatch] 'log_stream_name' or 'log_stream_prefix' "
                  "is required");
        goto error;
    }

    tmp = flb_output_get_property("log_format", ins);
    if (tmp) {
        ctx->log_format = tmp;
    }

    tmp = flb_output_get_property("region", ins);
    if (tmp) {
        ctx->region = tmp;
    } else {
        flb_error("[out_cloudwatch] 'region' is a required field");
        goto error;
    }

    ctx->create_group = FLB_FALSE;
    tmp = flb_output_get_property("auto_create_group", ins);
    /* native plugins use On/Off as bool, the old Go plugin used true/false */
    if (tmp && (strcasecmp(tmp, "On") == 0 || strcasecmp(tmp, "true") == 0)) {
        ctx->create_group = FLB_TRUE;
    }


    ctx->group_created = FLB_FALSE;

    /* init log streams */
    if (ctx->log_stream_name) {
        ctx->stream.name = flb_sds_create(ctx->log_stream_name);
        if (!ctx->stream.name) {
            flb_errno();
            goto error;
        }
    } else {
        mk_list_init(&ctx->streams);
    }

    /* one tls instance for provider, one for cw client */
    ctx->cred_tls.context = flb_tls_context_new(FLB_TRUE,
                                                ins->tls_debug,
                                                ins->tls_vhost,
                                                ins->tls_ca_path,
                                                ins->tls_ca_file,
                                                ins->tls_crt_file,
                                                ins->tls_key_file,
                                                ins->tls_key_passwd);

    if (!ctx->cred_tls.context) {
        flb_error("[out_cloudwatch] Failed to create tls context");
        goto error;
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
        flb_error("[out_cloudwatch] Failed to create tls context");
        goto error;
    }

    ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                           &ctx->cred_tls,
                                                           "us-west-2",
                                                           NULL,
                                                           flb_aws_client_generator());
    if (!ctx->aws_provider) {
        flb_error("[out_cloudwatch] Failed to create AWS Credential Provider");
        goto error;
    }

    /* initialize credentials and set to sync mode */
    ctx->aws_provider->provider_vtable->sync(ctx->aws_provider);
    ctx->aws_provider->provider_vtable->get_credentials(ctx->aws_provider);

    ctx->endpoint = flb_aws_endpoint("logs", (char *) ctx->region);
    if (!ctx->endpoint) {
        goto error;
    }

    struct flb_aws_client_generator *generator = flb_aws_client_generator();
    ctx->cw_client = generator->create();
    if (!ctx->cw_client) {
        goto error;
    }
    ctx->cw_client->name = "cw_client";
    ctx->cw_client->has_auth = FLB_TRUE;
    ctx->cw_client->provider = ctx->aws_provider;
    ctx->cw_client->region = (char *) ctx->region;
    ctx->cw_client->service = "logs";
    ctx->cw_client->port = 443;
    ctx->cw_client->flags = 0;
    ctx->cw_client->proxy = NULL;
    ctx->cw_client->static_headers = &content_type_header;
    ctx->cw_client->static_headers_len = 1;

    struct flb_upstream *upstream = flb_upstream_create(config, ctx->endpoint,
                                                        443, FLB_IO_TLS,
                                                        &ctx->client_tls);
    if (!upstream) {
        flb_error("[aws_credentials] Connection initialization error");
        goto error;
    }

    /*
     * Remove async flag from upstream
     * CW output runs in sync mode; because the CW API currently requires
     * PutLogEvents requests to a log stream to be made serially
     */
    upstream->flags &= ~(FLB_IO_ASYNC);

    ctx->cw_client->upstream = upstream;
    ctx->cw_client->host = ctx->endpoint;

    /* initialize out_buf */

    /*
     * TODO: should intelligently increase it's size as needed instead of
     * initing to max payload value
     */
    ctx->out_buf = flb_malloc(sizeof(char) * PUT_LOG_EVENTS_PAYLOAD_SIZE);
    if (!ctx->out_buf) {
        flb_free(ctx);
        return -1;
    }
    ctx->out_buf_size = PUT_LOG_EVENTS_PAYLOAD_SIZE;

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;

error:
    flb_error("[out_cloudwatch] Initialization failed");
    //TODO: clean up context function
    return -1;
}

static void cb_cloudwatch_flush(const void *data, size_t bytes,
                                const char *tag, int tag_len,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    struct flb_cloudwatch *ctx = out_context;
    int ret;
    int event_count;
    struct log_stream *stream = NULL;
    (void) i_ins;
    (void) config;

    if (ctx->create_group == FLB_TRUE && ctx->group_created == FLB_FALSE) {
        ret = create_log_group(ctx);
        if (ret < 0) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    stream = get_log_stream(ctx, tag, tag_len);
    if (!stream) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    // if (ctx->stream_created == FLB_FALSE) {
    //     ret = create_log_stream(ctx);
    //     if (ret < 0) {
    //         FLB_OUTPUT_RETURN(FLB_RETRY);
    //     }
    // }

    /*
     *  1. Parse msgpack to events
     *  2. Sort events on timestamp
     *  3. Send to CW in batches
     */
    event_count = msg_pack_to_events(ctx, data, bytes);
    if (event_count < 0) {
        flb_debug("Could not convert message pack to events");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    //TODO: should sort individual batches
    // Also sort an array of pointers to this list, not the actual data
    qsort(ctx->events, event_count, sizeof(struct event), compare_events);

    ret = send_in_batches(ctx, stream, event_count);
    if (ret < 0) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_cloudwatch_exit(void *data, struct flb_config *config)
{
    struct flb_cloudwatch *ctx = data;

    if (!ctx) {
        return 0;
    }

    //TODO

    flb_free(ctx);
    return 0;
}

void log_stream_destroy(struct log_stream *stream)
{
    if (stream) {
        if (stream->name) {
            flb_sds_destroy(stream->name);
        }
        if (stream->sequence_token) {
            flb_sds_destroy(stream->sequence_token);
        }
        flb_free(stream);
    }
}

/* Plugin registration */
struct flb_output_plugin out_cloudwatch_logs_plugin = {
    .name         = "cloudwatch_logs",
    .description  = "Send logs to Amazon CloudWatch",
    .cb_init      = cb_cloudwatch_init,
    .cb_flush     = cb_cloudwatch_flush,
    .cb_exit      = cb_cloudwatch_exit,
    .flags        = 0,
};
