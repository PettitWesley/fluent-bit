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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <stdio.h>
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

    char *role_arn = NULL;
    char *external_id = NULL;
    struct flb_aws_client_generator *generator;
    char *session_name;

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

    ctx->store.ins = ctx->ins;
    ctx->store.dir = ctx->buffer_dir;
    mk_list_init(&ctx->store.chunks);

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
    return -1;
}

/*
 * The S3 file name is
 * /<prefix>/-<datestamp>
 */
static flb_sds_t get_s3_key(struct flb_stdout *ctx)
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

    strftime(datestamp, sizeof(datestamp) - 1, "%Y/%m/%d/%H/%M:%S", &gmt);

    uri = flb_sds_create_size(strlen(ctx->prefix) + 50);

    tmp = flb_sds_printf(&uri, "/%s/%s", ctx->prefix, datestamp);
    if (!tmp) {
        flb_sds_destroy(uri);
        return NULL;
    }
    uri = tmp;

    return uri;
}

static int s3_put_object(struct flb_stdout *ctx, char *buffered_data,
                         size_t buffer_size, flb_sds_t json)
{
    flb_sds_t uri = NULL;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    char *body;
    char *tmp;
    size_t body_len = buffer_size + flb_sds_len(json);

    uri = get_s3_key(ctx);
    if (!uri) {
        flb_plg_error(ctx->ins, "Failed to construct S3 Object Key");
        return -1;
    }

    body = flb_malloc(body_len + 1);
    if (!body) {
        flb_errno();
        flb_sds_destroy(uri);
        return -1;
    }
    tmp = memcpy(body, buffered_data, buffer_size);
    if (!tmp) {
        flb_errno();
        flb_free(body);
        flb_sds_destroy(uri);
        return -1;
    }
    tmp = memcpy(body + buffer_size, json, flb_sds_len(json));
    if (!tmp) {
        flb_errno();
        flb_free(body);
        flb_sds_destroy(uri);
        return -1;
    }
    body[body_len] = '\0';

    s3_client = ctx->s3_client;
    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                          uri, body, body_len,
                                          NULL, 0);
    if (c) {
        flb_plg_debug(ctx->ins, "PutObject http status=%d", c->resp.status);
        if (c->resp.status == 200) {
            flb_plg_info(ctx->ins, "Successfully uploaded object %s", uri);
            flb_sds_destroy(uri);
            flb_free(body);
            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "PutObject", ctx->ins);
        if (c->resp.data != NULL) {
            flb_plg_debug(ctx->ins, "Raw PutObject response: %s", c->resp.data);
        }
    }

    flb_plg_error(ctx->ins, "PutObject request failed");
    flb_sds_destroy(uri);
    flb_free(body);
    return -1;
}

static void cb_stdout_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    struct flb_stdout *ctx = out_context;
    flb_sds_t json = NULL;
    struct local_chunk *chunk;
    char *buffered_data = NULL;
    size_t buffer_size;
    int ret;
    int len;
    (void) i_ins;
    (void) config;

    json = flb_pack_msgpack_to_json_format(data, bytes,
                                           FLB_PACK_JSON_FORMAT_LINES,
                                           ctx->json_date_format,
                                           ctx->json_date_key);

    if (json == NULL) {
        flb_plg_error(ctx->ins, "Could not marshal msgpack to JSON");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    len = flb_sds_len(json);
    if (tag[tag_len] != '\0') {
        flb_error("Tag is not null delimited");
    }
    chunk = get_chunk(&ctx->store, tag);

    if (chunk == NULL || (chunk->size + len) < CHUNKED_UPLOAD_SIZE) {
        /* add data to local buffer */
        ret = buffer_data(&ctx->store, chunk, tag, json, (size_t) len);
        flb_sds_destroy(json);
        if (ret < 0) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /* remove chunk from buffer list- needed for async http so that the
     * same chunk won't be sent more than once
     */
    mk_list_del(&chunk->_head);

    ret = flb_read_file(chunk->file_path, &buffered_data, &buffer_size);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                      chunk->file_path);
    }

    ret = s3_put_object(ctx, buffered_data, buffer_size, json);
    flb_sds_destroy(json);
    if (ret < 0) {
        return FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* delete the local buffer */
    ret = remove(chunk->file_path);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not delete local buffer file %s",
                      chunk->file_path);
    }
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
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    "Specifies the format of the date. Supported formats are double, iso8601 and epoch."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout, json_date_key),
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", "firenosed-dolphin-bucket",
     0, FLB_TRUE, offsetof(struct flb_stdout, bucket),
    "S3 bucket name."
    },
    {
     FLB_CONFIG_MAP_STR, "region", "us-east-1",
     0, FLB_TRUE, offsetof(struct flb_stdout, region),
    "AWS region."
    },

    {
     FLB_CONFIG_MAP_STR, "buffer_dir", "/fluent-bit/buffer/s3",
     0, FLB_TRUE, offsetof(struct flb_stdout, buffer_dir),
    "Directory to locally buffer data before sending. Plugin uses the S3 Multipart "
    "upload API to send data in chunks of 5 MB at a time- only a small amount of"
    " data will be locally buffered at any given point in time."
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
