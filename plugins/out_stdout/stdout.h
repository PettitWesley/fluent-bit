/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_OUT_STDOUT
#define FLB_OUT_STDOUT


#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

struct event {
    char *json;
    size_t len;
    // TODO: re-usable in kinesis streams plugin if we make it timespec instead
    unsigned long long timestamp;
};

struct flb_stdout {
    int out_format;
    int json_date_format;
    flb_sds_t json_date_key;

    struct event *events;
    size_t events_size;

    /*
     * for performance, allocate large buffers at first flush and then re-use
     * till the plugin exits
     */
    char *tmp_buf;
    size_t tmp_buf_size;
    char *out_buf;
    size_t out_buf_size;
};

#endif
