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

#ifndef FLB_OUT_CLOUDWATCH_LOGS_H
#define FLB_OUT_CLOUDWATCH_LOGS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>

struct event {
    char *json;
    size_t len;
    // TODO: re-usable in kinesis streams plugin if we make it timespec instead
    // uint64_t?
    unsigned long long timestamp;
};

// type logStream struct {
// 	logEvents         []*cloudwatchlogs.InputLogEvent
// 	currentByteLength int
// 	currentBatchStart *time.Time
// 	currentBatchEnd   *time.Time
// 	nextSequenceToken *string
// 	logStreamName     string
// 	expiration        time.Time
// }

struct log_stream {
    flb_sds_t name;
    flb_sds_t sequence_token;
    /*
     * log streams in CloudWatch do not expire; but our internal representations
     * of them are periodically cleaned up if they have been unused for too long
     */
    time_t expiration;

    struct mk_list _head;
};

void log_stream_destroy(struct log_stream *stream);

struct flb_cloudwatch {
    struct flb_tls cred_tls;
    struct flb_tls client_tls;
    struct flb_aws_provider *aws_provider;
    struct flb_aws_client *cw_client;

    /* configuration options */
    const char *log_stream_name;
    const char *log_stream_prefix;
    const char *log_group;
    const char *region;
    const char *log_format;
    /* Should the plugin create the log group */
    int create_group;

    char *endpoint;
    /* has the log group successfully been created */
    int group_created;

    struct event *events;
    size_t events_size;

    /* if we're writing to a static log stream, we'll use this */
    struct log_stream stream;
    /* if the log stream is dynamic, we'll use this */
    struct mk_list streams;

    /*
     * for performance, allocate large buffers at first flush and then re-use
     * till the plugin exits
     */
    char *tmp_buf;
    size_t tmp_buf_size;
    char *out_buf;
    size_t out_buf_size;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

#endif
