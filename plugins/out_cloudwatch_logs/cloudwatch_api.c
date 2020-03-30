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

#define ERR_CODE_ALREADY_EXISTS         "ResourceAlreadyExistsException"
#define ERR_CODE_INVALID_SEQUENCE_TOKEN "InvalidSequenceTokenException"

#define ONE_DAY_IN_MILLISECONDS        86400000
#define FOUR_HOURS_IN_SECONDS              14400

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

static struct flb_aws_header put_log_events_header[] = {
    {
        .key = "X-Amz-Target",
        .key_len = 12,
        .val = "Logs_20140328.PutLogEvents",
        .val_len = 26,
    },
    {
        .key = "x-amzn-logs-format",
        .key_len = 18,
        .val = "",
        .val_len = 0,
    },
};

/*
 * Parses all incoming msgpack records to events and stores them in the ctx
 * events pointer. Uses the ctx tmp_buf to store the JSON strings.
 *
 * Return value is number of events created, or -1 on error.
 */
int msg_pack_to_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                       const char *data, size_t bytes)
{
    size_t off = 0;
    size_t size;
    int new_len;
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
     * tmp_buf needs to hold a json representation of the msgpack
     * 'size' is a safe estimate for the amount of memory needed
     * TODO: Need to re-alloc in loop if needed
     */
    // size = 3 * bytes + 100;
    size = 2 * bytes + 100;
    if (buf->tmp_buf == NULL) {
        flb_plg_debug(ctx->ins, "Increasing tmp_buf to %zu", size);
        buf->tmp_buf = flb_malloc(size);
        if (!buf->tmp_buf) {
            flb_errno();
            return -1;
        }
        buf->tmp_buf_size = size;
    }
    else if (buf->tmp_buf_size < size) {
        flb_plg_debug(ctx->ins, "Increasing tmp_buf to %zu", size);
        if (buf->tmp_buf) {
            flb_free(buf->tmp_buf);
            buf->tmp_buf = NULL;
        }
        buf->tmp_buf = flb_malloc(size);
        if (!buf->tmp_buf) {
            flb_errno();
            return -1;
        }
        buf->tmp_buf_size = size;
    }

    /* initialize events if needed */
    if (buf->events == NULL) {
        buf->events = flb_malloc(sizeof(struct event) * 5000);
        if (!buf->events) {
            flb_errno();
            return -1;
        }
        buf->events_capacity = 5000;
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
        if (i >= buf->events_capacity) {
            new_len = buf->events_capacity * 2;
            size = sizeof(struct event) * new_len;
            flb_plg_debug(ctx->ins, "Increasing event buffer to %d", new_len);
            buf->events = flb_realloc(buf->events, size);
            if (!buf->events) {
                flb_errno();
                goto error;
            }
            buf->events_capacity = new_len;
        }

        /* re-alloc tmp_buf if needed */

        // TODO: make log key a separate function
        if (ctx->log_key) {
            msgpack_object_kv *kv;
            msgpack_object  key;
            msgpack_object  val;
            char *key_str = NULL;
            size_t key_str_size = 0;
            int j;
            int check = FLB_FALSE;
            int found = FLB_FALSE;

            kv = map.via.map.ptr;

            for(j=0; j < map_size; j++) {
                key = (kv+j)->key;
                if (key.type == MSGPACK_OBJECT_BIN) {
                    key_str  = (char *) key.via.bin.ptr;
                    key_str_size = key.via.bin.size;
                    check = FLB_TRUE;
                }
                if (key.type == MSGPACK_OBJECT_STR) {
                    key_str  = (char *) key.via.str.ptr;
                    key_str_size = key.via.str.size;
                    check = FLB_TRUE;
                }

                if (check == FLB_TRUE) {
                    if (strncmp(ctx->log_key, key_str, key_str_size) == 0) {
                        found = FLB_TRUE;
                        val = (kv+j)->val;
                        /* set tmp_buf_ptr before using it */
                        tmp_buf_ptr = buf->tmp_buf + tmp_buf_offset;
                        written = flb_msgpack_to_json(tmp_buf_ptr,
                                                      buf->tmp_buf_size - tmp_buf_offset,
                                                      &val);
                        if (written < 0) {
                            flb_plg_error(ctx->ins, "Failed to convert msgpack value to JSON");
                            goto error;
                        }
                        /* Discard empty messages (written == 2 means '""') */
                        if (written <= 2) {
                            flb_plg_debug(ctx->ins, "Found empty log message");
                            continue;
                        }
                        /*
                         * flb_msgpack_to_json will encase the value in quotes
                         * We don't want that for log_key, so we remove the first
                         * and last character
                         */
                        written--;
                        tmp_buf_ptr++;
                        tmp_buf_offset += written;
                        event = &buf->events[i];
                        event->json = tmp_buf_ptr;
                        event->len = written - 1;
                        event->timestamp = (unsigned long long) (tms.tm.tv_sec * 1000 +
                                                                 tms.tm.tv_nsec/1000000);

                    }
                }

            }
            if (found == FLB_FALSE) {
                flb_plg_error(ctx->ins, "Could not find log_key '%s' in record",
                              ctx->log_key);
            }
            else {
                i++;
            }
            continue;
        }

        /* set tmp_buf_ptr before using it */
        tmp_buf_ptr = buf->tmp_buf + tmp_buf_offset;
        written = flb_msgpack_to_json(tmp_buf_ptr,
                                      buf->tmp_buf_size - tmp_buf_offset,
                                      &map);
        if (written < 0) {
            flb_plg_error(ctx->ins, "Failed to convert msgpack record to JSON");
            goto error;
        }
        /* Discard empty messages (written == 2 means '""') */
        if (written <= 2) {
            flb_plg_debug(ctx->ins, "Found empty log message");
            continue;
        }
        tmp_buf_offset += written;
        event = &buf->events[i];
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
static int init_put_payload(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                            struct log_stream *stream, int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"logGroupName\":\"", 17)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ctx->log_group, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",\"logStreamName\":\"", 19)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      stream->name, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",", 2)) {
        goto error;
    }

    if (stream->sequence_token) {
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          "\"sequenceToken\":\"", 17)) {
            goto error;
        }

        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          stream->sequence_token, 0)) {
            goto error;
        }

        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          "\",", 2)) {
            goto error;
        }
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
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
static int add_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                     struct event *event, int *offset)
{
    char ts[50];

    if (!sprintf(ts, "%llu", event->timestamp)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"timestamp\":", 13)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ts, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ",\"message\":\"", 12)) {
        goto error;
    }

    if (ctx->log_key != NULL) {
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          event->json, event->len)) {
            goto error;
        }
    }
    else {
        /* flb_utils_write_str will escape the JSON in event->json */
        if (!flb_utils_write_str(buf->out_buf, offset, buf->out_buf_size,
                                 event->json, event->len)) {
            goto error;
        }
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"}", 2)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/* Terminates a PutLogEvents payload */
static int end_put_payload(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                           int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "]}", 2)) {
        return -1;
    }
    buf->out_buf[*offset] = '\0';

    return 0;
}

struct log_stream *get_dynamic_log_stream(struct flb_cloudwatch *ctx,
                                          const char *tag, int tag_len)
{
    struct log_stream *new_stream;
    struct log_stream *stream;
    struct mk_list *tmp;
    struct mk_list *head;
    flb_sds_t name = NULL;
    flb_sds_t tmp_s = NULL;
    int ret;

    name = flb_sds_create(ctx->log_stream_prefix);
    if (!name) {
        flb_errno();
        return NULL;
    }

    tmp_s = flb_sds_cat(name, tag, tag_len);
    if (!tmp_s) {
        flb_errno();
        flb_sds_destroy(name);
        return NULL;
    }
    name = tmp_s;

    /* check if the stream already exists */
    mk_list_foreach_safe(head, tmp, &ctx->streams) {
        stream = mk_list_entry(head, struct log_stream, _head);
        if (strcmp(name, stream->name) == 0) {
            flb_sds_destroy(name);
            return stream;
        } else {
            /* check if stream is expired, if so, clean it up */
            if (stream->expiration < time(NULL)) {
                mk_list_del(&stream->_head);
                log_stream_destroy(stream);
            }
        }
    }

    /* create the new stream */
    new_stream = flb_calloc(1, sizeof(struct log_stream));
    if (!new_stream) {
        flb_errno();
        flb_sds_destroy(name);
        return NULL;
    }
    new_stream->name = name;

    ret = create_log_stream(ctx, new_stream);
    if (ret < 0) {
        log_stream_destroy(new_stream);
        return NULL;
    }
    new_stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;

    mk_list_add(&new_stream->_head, &ctx->streams);
    return new_stream;
}

struct log_stream *get_log_stream(struct flb_cloudwatch *ctx,
                                  const char *tag, int tag_len)
{
    struct log_stream *stream;
    int ret;

    if (ctx->log_stream_name) {
        stream = &ctx->stream;
        if (ctx->stream_created == FLB_FALSE) {
            ret = create_log_stream(ctx, stream);
            if (ret < 0) {
                return NULL;
            }
            stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;
            ctx->stream_created = FLB_TRUE;
        }
        return stream;
    }

     return get_dynamic_log_stream(ctx, tag, tag_len);
}

static unsigned long long stream_time_span(struct log_stream *stream,
                                           struct event *event)
{
    if (stream->oldest_event == 0 || stream->newest_event == 0) {
        return 0;
    }

    if (stream->oldest_event > event->timestamp) {
        return stream->newest_event - event->timestamp;
    } else if (stream->newest_event < event->timestamp) {
        return event->timestamp - stream->oldest_event;
    }

    return stream->newest_event - stream->oldest_event;
}

/* returns FLB_TRUE if time span is less than 24 hours, FLB_FALSE if greater */
static int check_stream_time_span(struct log_stream *stream,
                                  struct event *event)
{
    unsigned long long span = stream_time_span(stream, event);

    if (span < ONE_DAY_IN_MILLISECONDS) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* sets the oldest_event and newest_event fields */
static void set_stream_time_span(struct log_stream *stream, struct event *event)
{
    if (stream->oldest_event == 0 || stream->oldest_event > event->timestamp) {
        stream->oldest_event = event->timestamp;
    }

    if (stream->newest_event == 0 || stream->newest_event < event->timestamp) {
        stream->newest_event = event->timestamp;
    }
}

/*
 * Send one batch to CW of 10,000 events or 1 MB
 */
int send_one_batch(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                   struct log_stream *stream,
                   int first_event, int event_count)
{
    int ret;
    int offset;
    int i;
    struct event *event;
    /* last event in the list that we will try to send in this single put */
    int last_event = event_count;
    /* tracks how many events we were able to send in this put */
    int events_sent;

    if ((event_count - first_event) > MAX_EVENTS_PER_PUT) {
        last_event = first_event + MAX_EVENTS_PER_PUT;
    }

retry:
    stream->newest_event = 0;
    stream->oldest_event = 0;

    events_sent = first_event;
    offset = 0;
    ret = init_put_payload(ctx, buf, stream, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to initialize PutLogEvents payload");
        return -1;
    }

    for (i = first_event; i < last_event; i++) {
        event = &buf->events[i];

        if (check_stream_time_span(stream, event) == FLB_FALSE) {
            /* decrement offset, to remove the "," written for the last event */
            offset--;
            break;
        }

        /*
         * check that we have room left for this event
         *
         * offset will accurately track the true number of bytes written so far.
         * Until written, we do know the size of the event, it must be escaped.
         * Multiplying it's length by 2 ensures we are guaranteed to be safe.
         * 30 is the number of bytes that add_event writes in addition to the
         * actual event.
         */
        if ((offset + event->len * 2 + PUT_LOG_EVENTS_FOOTER_LEN + 30)
             > PUT_LOG_EVENTS_PAYLOAD_SIZE) {
            flb_plg_debug(ctx->ins, "Terminating payload event=%d, offset=%d",
                          i - first_event, offset);
            /* decrement offset, to remove the "," written for the last event */
            offset--;
            break;
        }
        ret = add_event(ctx, buf, event, &offset);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write log event %d to "
                          "payload buffer", i - first_event);
            return -1;
        }
        if (i != (last_event - 1)) {
            if (!try_to_write(buf->out_buf, &offset, buf->out_buf_size,
                              ",", 1)) {
                flb_plg_error(ctx->ins, "Could not terminate log event with ','");
                return -1;
            }
        }

        set_stream_time_span(stream, event);
        events_sent++;
    }

    ret = end_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not complete PutLogEvents payload");
        return -1;
    }

    flb_plg_debug(ctx->ins, "Sending %d events", events_sent - first_event);
    ret = put_log_events(ctx, buf, stream, (size_t) offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to send log events");
        return -1;
    } else if (ret > 0) {
        goto retry;
    }

    return events_sent;
}

int send_in_batches(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                    struct log_stream *stream, int event_count)
{
    int offset = 0;

    while (offset < event_count) {
        offset = send_one_batch(ctx, buf, stream, offset, event_count);
        if (offset < 0) {
            return -1;
        }
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

    flb_plg_info(ctx->ins, "Creating log group %s", ctx->log_group);

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
        flb_plg_debug(ctx->ins, "CreateLogGroup http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Created log group %s", ctx->log_group);
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
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                        "CreateLogGroup", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error can not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to create log group");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

int create_log_stream(struct flb_cloudwatch *ctx, struct log_stream *stream)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;

    flb_plg_info(ctx->ins, "Creating log stream %s in log group %s",
                 stream->name, ctx->log_group);

    body = flb_sds_create_size(50 + strlen(ctx->log_group) +
                               strlen(stream->name));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogStream request body */
    tmp = flb_sds_printf(&body,
                         "{\"logGroupName\":\"%s\",\"logStreamName\":\"%s\"}",
                         ctx->log_group,
                         stream->name);
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
        flb_plg_debug(ctx->ins,"CreateLogStream http status=%d",
                      c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Created log stream %s", stream->name);
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
                                 stream->name);
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    return 0;
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "CreateLogStream", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error can not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to create log stream");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

/*
 * Returns -1 on failure, 0 on success, and 1 for a sequence token error,
 * which means the caller can retry.
 */
int put_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                   struct log_stream *stream, size_t payload_size)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t tmp;
    flb_sds_t error;
    int num_headers = 1;

    flb_plg_debug(ctx->ins, "Sending log events to log stream %s", stream->name);

    /* stream is being used, update expiration */
    stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;

    if (ctx->log_format != NULL) {
        put_log_events_header[1].val = (char *) ctx->log_format;
        put_log_events_header[1].val_len = strlen(ctx->log_format);
        num_headers = 2;
    }

    cw_client = ctx->cw_client;
    c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                          "/", buf->out_buf, payload_size,
                                          put_log_events_header, num_headers);
    if (c) {
        flb_plg_debug(ctx->ins, "PutLogEvents http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_debug(ctx->ins, "Sent events to %s", stream->name);
            if (c->resp.payload_size > 0) {
                tmp = flb_json_get_val(c->resp.payload, c->resp.payload_size,
                                       "nextSequenceToken");
                if (tmp) {
                    if (stream->sequence_token != NULL) {
                        flb_sds_destroy(stream->sequence_token);
                    }
                    stream->sequence_token = tmp;
                }
                else {
                    flb_plg_error(ctx->ins, "Could not find sequence token in "
                                  "response: %s", c->resp.payload);
                }
            }
            else {
                flb_plg_error(ctx->ins, "Could not find sequence token in "
                              "response: response body is empty");
            }
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_INVALID_SEQUENCE_TOKEN) == 0) {
                    /*
                     * This case will happen when we do not know the correct
                     * sequence token; we can find it in the error response
                     * and retry.
                     */
                    flb_plg_debug(ctx->ins, "Sequence token was invalid, "
                                  "will retry");
                    tmp = flb_json_get_val(c->resp.payload, c->resp.payload_size,
                                           "expectedSequenceToken");
                    if (tmp) {
                        if (stream->sequence_token != NULL) {
                            flb_sds_destroy(stream->sequence_token);
                        }
                        stream->sequence_token = tmp;
                        flb_sds_destroy(error);
                        flb_http_client_destroy(c);
                        /* tell the caller to retry */
                        return 1;
                    }
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "PutLogEvents", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error could not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to send log events");
    if (c) {
        flb_http_client_destroy(c);
    }
    return -1;
}


void cw_flush_destroy(struct cw_flush *buf)
{
    if (buf) {
        flb_free(buf->tmp_buf);
        flb_free(buf->out_buf);
        flb_free(buf->events);
        flb_free(buf);
    }
}
