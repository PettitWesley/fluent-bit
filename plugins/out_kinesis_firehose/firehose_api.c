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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_macros.h>
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
#include <stdio.h>

#include "firehose_api.h"

#define ERR_CODE_SERVICE_UNAVAILABLE "ServiceUnavailableException"

static struct flb_aws_header put_record_batch_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Firehose_20150804.PutRecordBatch",
    .val_len = 32,
};

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
 * Writes the "header" for a put_record_batch payload
 */
static int init_put_payload(struct flb_firehose *ctx, struct flush *buf,
                            int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"DeliveryStreamName\":\"", 23)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ctx->delivery_stream, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",\"Records\":[", 13)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/*
 * Writes a log event to the output buffer
 */
static int write_event(struct flb_firehose *ctx, struct flush *buf,
                       struct event *event, int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"Data\":\"", 8)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      event->json, event->len)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"}", 2)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/* Terminates a PutRecordBatch payload */
static int end_put_payload(struct flb_firehose *ctx, struct flush *buf,
                           int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "]}", 2)) {
        return -1;
    }
    buf->out_buf[*offset] = '\0';

    return 0;
}


/*
 * Processes the msgpack object
 * Returns 0 on success, -1 on general errors,
 * and 1 if we ran out of space to write the event
 * which means a send must occur
 */
static int process_event(struct flb_firehose *ctx, struct flush *buf,
                         const msgpack_object *obj, struct flb_time *tms)
{
    size_t written;
    int ret;
    size_t size;
    int offset = 0;
    struct event *event;
    char *tmp_buf_ptr;

    tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
    ret = flb_msgpack_to_json(tmp_buf_ptr,
                                  buf->tmp_buf_size - buf->tmp_buf_offset,
                                  obj);
    if (ret < 0) {
        /*
         * negative value means failure to write to buffer,
         * which means we ran out of space, and must send the logs
         *
         * TODO: This could also incorrectly be triggered if the record
         * is larger than MAX_EVENT_SIZE
         */
        return 1;
    }
    written = (size_t) ret;
    /* Discard empty messages (written == 2 means '""') */
    if (written <= 2) {
        flb_plg_debug(ctx->ins, "Found empty log message");
        return 0;
    }

    if (written >= MAX_EVENT_SIZE) {
        flb_plg_warn(ctx->ins, "Discarding record which is larger than "
                     "max size allowed by Firehose");
        return 0;
    }

    /* the json string must be escaped, unless the log_key option is used */
    if (ctx->log_key == NULL) {
        /*
         * check if event_buf is initialized and big enough
         * If all chars need to be hex encoded (impossible), 6x space would be
         * needed
         */
        size = written * 6;
        if (buf->event_buf == NULL || buf->event_buf_size < size) {
            flb_free(buf->event_buf);
            buf->event_buf = flb_malloc(size);
            buf->event_buf_size = size;
            if (buf->event_buf == NULL) {
                flb_errno();
                return -1;
            }
        }
        offset = 0;
        if (!flb_utils_write_str(buf->event_buf, &offset, size,
                                 tmp_buf_ptr, written)) {
            return -1;
        }
        written = offset;

        if (written >= MAX_EVENT_SIZE) {
            flb_plg_warn(ctx->ins, "Discarding record which is larger than "
                         "max size allowed by Firehose");
            return 0;
        }

        tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
        if ((buf->tmp_buf_size - buf->tmp_buf_offset) < written) {
            /* not enough space, send logs */
            return 1;
        }

        /* copy serialized json to tmp_buf */
        if (!strncpy(tmp_buf_ptr, buf->event_buf, written)) {
            return -1;
        }

        buf->tmp_buf_offset += written;
        event = &buf->events[buf->event_index];
        event->json = tmp_buf_ptr;
        event->len = written;
        event->timestamp.tv_sec = tms->tm.tv_sec;
        event->timestamp.tv_nsec = tms->tm.tv_nsec;

    }
    else {
        /*
         * flb_msgpack_to_json will encase the value in quotes
         * We don't want that for log_key, so we ignore the first
         * and last character
         */
        written--;
        tmp_buf_ptr++;
        buf->tmp_buf_offset += written;
        written--;
        event = &buf->events[buf->event_index];
        event->json = tmp_buf_ptr;
        event->len = written;
        event->timestamp.tv_sec = tms->tm.tv_sec;
        event->timestamp.tv_nsec = tms->tm.tv_nsec;
    }

    return 0;
}

/* Resets or inits a flush struct */
static void reset_flush_buf(struct flb_firehose *ctx, struct flush *buf) {
    buf->event_index = 0;
    buf->tmp_buf_offset = 0;
    buf->event_index = 0;
    buf->data_size = PUT_RECORD_BATCH_HEADER_LEN + PUT_RECORD_BATCH_FOOTER_LEN;
    buf->data_size += strlen(ctx->delivery_stream);
}

/* constructs a put payload, and then sends */
static int send_log_events(struct flb_firehose *ctx, struct flush *buf) {
    int ret;
    int offset;
    int i;
    struct event *event;

    if (buf->event_index == 0) {
        return 0;
    }

    /* alloc out_buf if needed */
    if (buf->out_buf == NULL || buf->out_buf_size < buf->data_size) {
        if (buf->out_buf != NULL) {
            flb_free(buf->out_buf);
        }
        buf->out_buf = flb_malloc(buf->data_size);
        if (!buf->out_buf) {
            flb_errno();
            flush_destroy(buf);
            return NULL;
        }
        buf->out_buf_size = buf->data_size;
    }

    offset = 0;
    ret = init_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to initialize PutRecordBatch payload");
        return -1;
    }

    for (i = 0; i < buf->event_index; i++) {
        event = &buf->events[i];
        ret = write_event(ctx, buf, event, &offset);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write log record %d to "
                          "payload buffer", i);
            return -1;
        }
        if (i != (buf->event_index - 1)) {
            if (!try_to_write(buf->out_buf, &offset, buf->out_buf_size,
                              ",", 1)) {
                flb_plg_error(ctx->ins, "Could not terminate record with ','");
                return -1;
            }
        }
    }

    ret = end_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not complete PutRecordBatch payload");
        return -1;
    }

    flb_plg_debug(ctx->ins, "Sending %d records", i);
    ret = put_record_batch(ctx, buf, (size_t) offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to send log records");
        return -1;
    }

    return 0;
}

/*
 * Processes the msgpack object, sends the current batch if needed
 */
static int add_event(struct flb_firehose *ctx, struct flush *buf,
                     const msgpack_object *obj, struct flb_time *tms)
{
    int ret;
    struct event *event;
    int retry_add = FLB_FALSE;
    int event_bytes = 0;

    if (buf->event_index == 0) {
        /* init */
        reset_flush_buf(ctx, buf);
    }

retry_add_event:
    retry_add = FLB_FALSE;
    ret = process_event(ctx, buf, obj, tms);
    if (ret < 0) {
        return -1;
    }
    else if (ret > 0) {
        /* send logs and then retry the add */
        buf->event_index--;
        retry_add = FLB_TRUE;
        goto send;
    }

    event = &buf->events[buf->event_index];
    event_bytes = event->len + PUT_RECORD_BATCH_PER_RECORD_LEN;

    if ((buf->data_size + event_bytes) > PUT_RECORD_BATCH_PAYLOAD_SIZE) {
        /* do not send this event */
        buf->event_index--;
        retry_add = FLB_TRUE;
        goto send;
    }

    if (buf->event_index == MAX_EVENTS_PER_PUT) {
        goto send;
    }

    /* send is not needed yet, return to caller */
    buf->data_size += event_bytes;
    buf->event_index++;

    return 0;

send:
    ret = send_log_events(ctx, buf);
    reset_flush_buf(ctx, buf);
    if (ret < 0) {
        return -1;
    }

    if (retry_add == FLB_TRUE) {
        goto retry_add_event;
    }

    return 0;
}

/*
 * Main routine- processes msgpack and sends in batches
 * return value is the number of events processed
 */
int process_and_send_records(struct flb_firehose *ctx, struct flush *buf,
                             const char *data, size_t bytes)
{
    size_t off = 0;
    int i = 0;
    size_t map_size;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object  map;
    msgpack_object root;
    msgpack_object_kv *kv;
    msgpack_object  key;
    msgpack_object  val;
    char *key_str = NULL;
    size_t key_str_size = 0;
    int j;
    int ret;
    int check = FLB_FALSE;
    int found = FLB_FALSE;
    struct flb_time tms;

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

        if (ctx->log_key) {
            key_str = NULL;
            key_str_size = 0;
            check = FLB_FALSE;
            found = FLB_FALSE;

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
                        ret = add_event(ctx, buf, &val, &tms);
                        if (ret < 0 ) {
                            goto error;
                        }
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

        ret = add_event(ctx, buf, &map, &tms);
        if (ret < 0 ) {
            goto error;
        }
        i++;
    }
    msgpack_unpacked_destroy(&result);

    /* send any remaining events */
    ret = send_log_events(ctx, buf);
    reset_flush_buf(ctx, buf);
    if (ret < 0) {
        return -1;
    }

    /* return number of events */
    return i;

error:
    msgpack_unpacked_destroy(&result);
    return -1;
}

/*
 * Returns -1 on failure, 0 on success
 */
int put_record_batch(struct flb_firehose *ctx, struct flush *buf,
                     size_t payload_size)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *firehose_client;
    flb_sds_t error;

    flb_plg_debug(ctx->ins, "Sending log records to delivery stream %s",
                  ctx->delivery_stream);

    firehose_client = ctx->firehose_client;
    c = firehose_client->client_vtable->request(firehose_client, FLB_HTTP_POST,
                                                "/", buf->out_buf, payload_size,
                                                &put_record_batch_header, 1);

    if (c) {
        flb_plg_debug(ctx->ins, "PutRecordBatch http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_debug(ctx->ins, "Sent events to %s", ctx->delivery_stream);
            if (c->resp.payload_size > 0) {
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_SERVICE_UNAVAILABLE) == 0) {
                    flb_plg_error(ctx->ins, "Throughput limits for %s "
                                  "may have been exceeded.",
                                  ctx->delivery_stream);
                }
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "PutRecordBatch", ctx->ins);
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


void flush_destroy(struct flush *buf)
{
    if (buf) {
        flb_free(buf->tmp_buf);
        flb_free(buf->out_buf);
        flb_free(buf->events);
        flb_free(buf->event_buf);
        flb_free(buf);
    }
}
