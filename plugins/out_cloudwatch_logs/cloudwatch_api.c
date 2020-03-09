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

#include "cloudwatch_api.h"

#define ERR_CODE_ALREADY_EXISTS     "ResourceAlreadyExistsException"

static struct flb_aws_header create_group_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.CreateLogGroup",
    .val_len = 28,
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

/*
 * Parses all incoming msgpack records to events and stores them in the ctx
 * events pointer. Uses the ctx tmp_buf to store the JSON strings.
 *
 * Return value is number of events created, or -1 on error.
 */
int msg_pack_to_events(struct flb_cloudwatch *ctx, const char *data, size_t bytes)
{
    size_t off = 0;
    size_t size;
    int i = 0;
    size_t tmp_buf_offset = 0;
    size_t written;
    size_t map_size;
    char *tmp_buf_ptr = NULL;
    struct flb_time tms;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object  map;
    msgpack_object root;
    struct event *event;

    /*
     * Check if tmp_buf is big enough.
     * Realistically, msgpack is never less than half the size of JSON
     * We allocate 3 times as much memory (plus a small constant)
     * just to be super safe.
     * Re-allocs are extremely expensive, having a bit of extra memory is not.
     */
    size = 3 * bytes + 100;
    if (ctx->tmp_buf == NULL) {
        flb_trace("Increasing tmp_buf to %zu", size);
        ctx->tmp_buf = flb_malloc(sizeof(char) * size);
        if (!ctx->tmp_buf) {
            flb_errno();
            return -1;
        }
        ctx->tmp_buf_size = (3 * bytes + 100);
    }
    else if (ctx->tmp_buf_size < size) {
        flb_trace("Increasing tmp_buf to %zu", size);
        flb_free(ctx->tmp_buf);
        ctx->tmp_buf = flb_malloc(sizeof(char) * size);
        if (!ctx->tmp_buf) {
            flb_errno();
            return -1;
        }
        ctx->tmp_buf_size = size;
    }

    /* initialize events if needed */
    if (ctx->events == NULL) {
        ctx->events = flb_malloc(sizeof(struct event) * 1000);
        if (!ctx->events) {
            flb_errno();
            return -1;
        }
        ctx->events_size = 1000;
    }

    /* unpack msgpack */

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map.
         */
         root = result.data;
         if (root.via.array.size != 2) {
             continue;
         }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* Get the record/map */
        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* re-alloc event buffer if needed */
        if (i > ctx->events_size) {
            size = ctx->events_size * 1.5;
            flb_trace("Increasing event buffer to %zu", size);
            ctx->events = flb_realloc(ctx->events, size);
            if (!ctx->events) {
                flb_errno();
                goto error;
            }
            ctx->events_size = size;
        }

        /* lack of space during iteration is unlikely; but check to be safe */
        size = tmp_buf_offset + 3 * map_size;
        if (size > ctx->tmp_buf_size) {
            flb_trace("In loop re-allocation of tmp_buf to %zu", size);
            ctx->tmp_buf = flb_realloc(ctx->tmp_buf, size);
            if (!ctx->tmp_buf) {
                flb_errno();
                goto error;
            }
            ctx->tmp_buf_size = size;
        }

        /* set tmp_buf_ptr before using it */
        tmp_buf_ptr = ctx->tmp_buf + tmp_buf_offset;
        written = flb_msgpack_to_json(tmp_buf_ptr,
                                      ctx->tmp_buf_size - tmp_buf_offset,
                                      &map);
        if (written < 0) {
            flb_error("Failed to convert msgpack record to JSON");
            goto error;
        }
        tmp_buf_offset += written;
        event = &ctx->events[i];
        event->json = tmp_buf_ptr;
        event->len = written;
        event->timestamp = (unsigned long long) (tms.tm.tv_sec * 1000 +
                                                 tms.tm.tv_nsec/1000000);

        i++;
    }
    msgpack_unpacked_destroy(&result);

    /* return number of events */
    return i;

error:
    msgpack_unpacked_destroy(&result);
    return -1;
}

int compare_events(const void *a_arg, const void *b_arg)
{
    struct event *r_a = (struct event *) a_arg;
    struct event *r_b = (struct event *) b_arg;

    if (r_a->timestamp < r_b->timestamp) {
        return -1;
    }
    else if (r_a->timestamp == r_b->timestamp) {
        return 0;
    }
    else {
        return 1;
    }
}

static inline int try_to_write(char *buf, int *off, size_t left,
                               const char *str, size_t str_len)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        return FLB_FALSE;
    }
    memcpy(buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}

/*
 * Writes the "header" for a put log events payload
 */
static int init_put_payload(struct flb_cloudwatch *ctx,
                            int *offset)
{
    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "{\"logGroupName\":\"", 17)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      ctx->log_group, 0)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "\",\"logStreamName\":\"", 19)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      ctx->log_stream, 0)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "\",", 2)) {
        goto error;
    }

    if (ctx->sequence_token) {
        if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                          "\"sequenceToken\":\"", 17)) {
            goto error;
        }

        if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                          ctx->sequence_token, 0)) {
            goto error;
        }

        if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                          "\",", 2)) {
            goto error;
        }
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "\"logEvents\":[", 13)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/*
 * Writes a log event to the output buffer
 */
static int add_event(struct flb_cloudwatch *ctx, struct event *event,
                     int *offset)
{
    char buf[50];

    if (!sprintf(buf, "%llu", event->timestamp)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "{\"timestamp\":", 13)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      buf, 0)) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      ",\"message\":\"", 12)) {
        goto error;
    }

    /* flb_utils_write_str will escape the JSON in event->json */
    if (!flb_utils_write_str(ctx->out_buf, offset, ctx->out_buf_size,
                             event->json, strlen(event->json))) {
        goto error;
    }

    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "\"}", 2)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/* Terminates a PutLogEvents payload */
static int end_put_payload(struct flb_cloudwatch *ctx, int *offset)
{
    if (!try_to_write(ctx->out_buf, offset, ctx->out_buf_size,
                      "]}", 2)) {
        return -1;
    }
    ctx->out_buf[*offset] = '\0';

    return 0;
}

/*
 * Send to CW in batches of 10,000 events or 1 MB
 * TODO: actually implement batching..
 */
int send_in_batches(struct flb_cloudwatch *ctx, int event_count)
{
    int ret;
    int offset = 0;
    int i;
    struct event *event;

    ret = init_put_payload(ctx, &offset);
    if (ret < 0) {
        flb_error("Failed to initialize PutLogEvents payload");
        return -1;
    }

    for (i = 0; i < event_count; i++) {
        event = &ctx->events[i];
        ret = add_event(ctx, event, &offset);
        if (ret < 0) {
            flb_error("Failed to write log event to payload buffer");
            return -1;
        }
        if (i != (event_count - 1)) {
            if (!try_to_write(ctx->out_buf, &offset, ctx->out_buf_size,
                              ",", 1)) {
                flb_error("Could not terminate log event with ','");
                return -1;
            }
        }
    }

    ret = end_put_payload(ctx, &offset);
    if (ret < 0) {
        flb_error("Could not complete PutLogEvents payload");
        return -1;
    }

    //printf("\n\nraw payload:\n%s\n", ctx->out_buf);

    flb_debug("[cloudwatch] Sending %d events", event_count);
    ret = put_log_events(ctx, (size_t) offset);
    if (ret < 0) {
        flb_error("[cloudwatch] Failed to send log events");
        return -1;
    }

    return 0;
}

int create_log_group(struct flb_cloudwatch *ctx)
{
    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;

    flb_info("[out_cloudwatch] Creating log group %s", ctx->log_group);

    body = flb_sds_create_size(25 + strlen(ctx->log_group));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogGroup request body */
    tmp = flb_sds_printf(&body, "{\"logGroupName\":\"%s\"}", ctx->log_group);
    if (!tmp) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }
    body = tmp;

    cw_client = ctx->cw_client;
    c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                          "/", body, strlen(body),
                                          &create_group_header, 1);

    if (c) {
        flb_debug("[out_cloudwatch] CreateLogGroup http status=%d",
                 c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_info("[out_cloudwatch] Created log group %s", ctx->log_group);
            ctx->group_created = FLB_TRUE;
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_ALREADY_EXISTS) == 0) {
                    flb_plg_info(ctx->ins, "Log Group %s already exists",
                                  ctx->log_group);
                    ctx->group_created = FLB_TRUE;
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    return 0;
                }
                else {
                    /* some other error occurred; notify user */
                    flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                        "CreateLogGroup", ctx->ins);
                }
                flb_sds_destroy(error);
            }
            else {
                /* error could not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_error("[out_cloudwatch] Failed to create log group");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

int create_log_stream(struct flb_cloudwatch *ctx)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;

    flb_info("[out_cloudwatch] Creating log stream %s in log group %s",
             ctx->log_stream, ctx->log_group);

    body = flb_sds_create_size(50 + strlen(ctx->log_group) +
                               strlen(ctx->log_stream));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogStream request body */
    tmp = flb_sds_printf(&body,
                         "{\"logGroupName\":\"%s\",\"logStreamName\":\"%s\"}",
                         ctx->log_group,
                         ctx->log_stream);
    if (!tmp) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }
    body = tmp;

    cw_client = ctx->cw_client;
    c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                          "/", body, strlen(body),
                                          &create_stream_header, 1);
    if (c) {
        flb_debug("[out_cloudwatch] CreateLogStream http status=%d",
                 c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_info("[out_cloudwatch] Created log stream %s", ctx->log_stream);
            ctx->stream_created = FLB_TRUE;
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_ALREADY_EXISTS) == 0) {
                    flb_plg_info(ctx->ins, "Log Stream %s already exists",
                                  ctx->log_stream);
                    ctx->stream_created = FLB_TRUE;
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    return 0;
                }
                else {
                    /* some other error occurred; notify user */
                    flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                        "CreateLogGroup", ctx->ins);
                }
                flb_sds_destroy(error);
            }
            else {
                /* error could not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_error("[out_cloudwatch] Failed to create log stream");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

int put_log_events(struct flb_cloudwatch *ctx, size_t payload_size)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t tmp;

    flb_debug("[out_cloudwatch] Sending log events to log stream %s",
              ctx->log_stream);

    cw_client = ctx->cw_client;
    c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                          "/", ctx->out_buf, payload_size,
                                          &put_log_events_header, 1);
    if (c) {
        flb_debug("[out_cloudwatch] PutLogEvents http status=%d",
                 c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_debug("[out_cloudwatch] Sent events to %s", ctx->log_stream);
            if (c->resp.payload_size > 0) {
                tmp = flb_json_get_val(c->resp.payload, c->resp.payload_size,
                                       "nextSequenceToken");
                if (tmp) {
                    ctx->sequence_token = tmp;
                }
                else {
                    flb_error("Could not find sequence token in response: %s",
                              c->resp.payload);
                }
            }
            else {
                flb_error("Could not find sequence token in response: "
                          "response body is empty");
            }
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        //TODO: process error code and get sequence token if needed
        if (c->resp.payload_size > 0) {
            flb_debug("[out_cloudwatch] Raw response: %s", c->resp.payload);
            flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                        "PutLogEvents", ctx->ins);
        }
    }

    flb_error("[out_cloudwatch] Failed to send log events");
    if (c) {
        flb_http_client_destroy(c);
    }
    return -1;
}
