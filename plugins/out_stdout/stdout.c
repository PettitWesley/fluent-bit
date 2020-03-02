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
#include <sys/time.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include "stdout.h"

static struct flb_aws_header content_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "application/x-amz-json-1.1",
    .val_len = 26,
};

static struct flb_aws_header create_stream_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.CreateLogStream",
    .val_len = 29,
};

static struct flb_aws_header put_log_events_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.PutLogEvents",
    .val_len = 26,
};

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
        flb_error("[out_cloudwatch] Failed to create AWS Credential Provider");
        return -1;
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
        flb_error("[out_cloudwatch] Failed to create AWS Credential Provider");
        return -1;
    }

    ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                           &ctx->cred_tls,
                                                           "us-west-2",
                                                           NULL,
                                                           flb_aws_client_generator());
    if (!ctx->aws_provider) {
        flb_error("[out_cloudwatch] Failed to create AWS Credential Provider");
        return -1;
    }

    /* initialize credentials */
    ctx->aws_provider->provider_vtable->init(ctx->aws_provider);

    ctx->endpoint = flb_aws_endpoint("logs", "us-west-2");
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
    ctx->cw_client->region = "us-west-2";
    ctx->cw_client->service = "logs";
    ctx->cw_client->port = 443;
    ctx->cw_client->flags = 0;
    ctx->cw_client->proxy = NULL;
    ctx->cw_client->static_headers = &content_type_header;
    ctx->cw_client->static_headers_len = 1;

    struct flb_upstream *upstream = flb_upstream_create(config, ctx->endpoint, 443,
                                   FLB_IO_TLS, &ctx->client_tls);
    if (!upstream) {
        flb_error("[aws_credentials] Connection initialization error");
        goto error;
    }

    /* Remove async flag from upstream */
    upstream->flags &= ~(FLB_IO_ASYNC);

    ctx->cw_client->upstream = upstream;
    ctx->cw_client->host = ctx->endpoint;

    /* for the prototype, just randomly generate a log stream name */
    ctx->log_stream = flb_sts_session_name();
    if (!ctx->log_stream) {
        goto error;
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;

error:
    flb_error("[out_cloudwatch] Initialization failed");
    return -1;
}

static int create_log_stream(struct flb_stdout *ctx,
                             char *log_group, char *log_stream)
{
    flb_info("[out_cloudwatch] Creating log stream %s in log group %s",
             log_stream, log_group);
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

    /* this works */
    if (ctx->stream_created == 0) {
        flb_info("creating stream..");
        struct flb_aws_header *create_stream_headers = flb_malloc(sizeof(struct flb_aws_header) * 2);
        if (!create_stream_headers) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        struct flb_http_client *c = NULL;
        flb_sds_t body = flb_sds_create_size(100);
        if (!body) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        create_stream_headers[0].key = "Content-Type";
        create_stream_headers[0].key_len = 12;
        create_stream_headers[0].val = "application/x-amz-json-1.1";
        create_stream_headers[0].val_len = 26;
        create_stream_headers[1].key = "X-Amz-Target";
        create_stream_headers[1].key_len = 12;
        create_stream_headers[1].val = "Logs_20140328.CreateLogStream";
        create_stream_headers[1].val_len = 29;

        /* create log stream */
        body = flb_sds_printf(&body, "{\"logGroupName\": \"fluent\",\"logStreamName\": \"%s\"}", ctx->log_stream);
        if (!body) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        struct flb_aws_client *cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body), create_stream_headers, 2);
        if (c) {
            flb_info("[out_cloudwatch] response status=%d", c->resp.status);
        }
        if (c->resp.status == 200) {
            ctx->stream_created = FLB_TRUE;
        }
        if (c && c->resp.payload_size > 0) {
            flb_info("resp: \n%s", c->resp.payload);
        }
    } else {
        flb_info("putting log events..");
        struct flb_aws_header *put_events_headers = flb_malloc(sizeof(struct flb_aws_header) * 2);
        if (!put_events_headers) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        struct flb_http_client *c = NULL;
        flb_sds_t body = flb_sds_create_size(100);
        if (!body) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        // TODO: a single static header and single dynamic header
        put_events_headers[0].key = "Content-Type";
        put_events_headers[0].key_len = 12;
        put_events_headers[0].val = "application/x-amz-json-1.1";
        put_events_headers[0].val_len = 26;
        put_events_headers[1].key = "X-Amz-Target";
        put_events_headers[1].key_len = 12;
        put_events_headers[1].val = "Logs_20140328.PutLogEvents";
        put_events_headers[1].val_len = 26;

        char *format = "{\"logGroupName\": \"fluent\",\"logStreamName\": \"%s\",\"logEvents\": [{\"timestamp\": %lld, \"message\": \"Example event 1\"},{\"timestamp\": %lld, \"message\": \"Example event 2\"},{\"timestamp\": %lld,\"message\": \"Example event 3\"}]}";
        char *format_token = "{\"sequenceToken\": \"%s\",\"logGroupName\": \"fluent\",\"logStreamName\": \"%s\",\"logEvents\": [{\"timestamp\": %lld, \"message\": \"Example event 1\"},{\"timestamp\": %lld, \"message\": \"Example event 2\"},{\"timestamp\": %lld,\"message\": \"Example event 3\"}]}";

        struct timeval tp;
        gettimeofday(&tp, NULL);
        long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
        flb_warn("time: %lld", ms);
        if (ctx->sequence_token == NULL) {
            body = flb_sds_printf(&body, format, ctx->log_stream, ms, ms, ms);
        } else {
            body = flb_sds_printf(&body, format_token, ctx->sequence_token, ctx->log_stream, ms, ms, ms);
        }
        if (!body) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        struct flb_aws_client *cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body), put_events_headers, 2);
        if (c) {
            flb_info("[out_cloudwatch] response status=%d", c->resp.status);
        }
        if (c && c->resp.payload_size > 0) {
            flb_info("resp: \n%s", c->resp.payload);
            if (c->resp.status == 200) {
                ctx->sequence_token = flb_json_get_val(c->resp.payload, c->resp.payload_size, "nextSequenceToken");
                flb_info("next token: \n%s", ctx->sequence_token);
            }
        }
    }

    flb_warn("original code after this...");
    FLB_OUTPUT_RETURN(FLB_OK);

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
