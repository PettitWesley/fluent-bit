/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_output.h>

int flb_sched_out_async_timer_cb_create(struct flb_sched *sched, int type, int ms,
                                        struct flb_output_instance *o_ins,
                                        char *job_name,
                                        void (*async_cb)(struct flb_config *, void *),
                                        void *data, struct flb_sched_timer **out_timer)
{
    flb_sds_t job_name;
    struct flb_out_async_timer_cb_data *timer_data;

    job_name = flb_sds_create(job_name);
    if (!job_name) {
        return;
    }

    timer_data = flb_calloc(1, sizeof(struct flb_out_async_timer_cb_data));
    if (!timer_data) {
        flb_sds_destroy(job_name);
        return;
    }

    timer_data->ins = o_ins;
    timer_data->job_name = job_name;
    timer_data->cb = async_cb;
    timer_data->data = data;

    return flb_sched_timer_cb_create(sched, type, ms, flb_out_async_sched_timer_cb, timer_data, NULL);
}