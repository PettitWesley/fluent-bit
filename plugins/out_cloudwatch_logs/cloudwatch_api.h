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

#ifndef FLB_OUT_CLOUDWATCH_API
#define FLB_OUT_CLOUDWATCH_API

// #define PUT_LOG_EVENTS_PAYLOAD_SIZE    1048576
// #define MAX_EVENTS_PER_PUT             10000

#define PUT_LOG_EVENTS_PAYLOAD_SIZE    1048576
#define MAX_EVENTS_PER_PUT             100

/* number of characters needed to 'end' a PutLogEvents payload */
#define PUT_LOG_EVENTS_FOOTER_LEN      4

#include "cloudwatch_logs.h"

int msg_pack_to_events(struct flb_cloudwatch *ctx, const char *data, size_t bytes);
int send_in_batches(struct flb_cloudwatch *ctx, struct log_stream *stream,
                    int event_count);
int create_log_stream(struct flb_cloudwatch *ctx, struct log_stream *stream);
struct log_stream *get_log_stream(struct flb_cloudwatch *ctx,
                                  const char *tag, int tag_len);
int put_log_events(struct flb_cloudwatch *ctx, struct log_stream *stream,
                   size_t payload_size);
int create_log_group(struct flb_cloudwatch *ctx);
int compare_events(const void *a_arg, const void *b_arg);

#endif
