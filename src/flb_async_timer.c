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
#include <fluent-bit/flb_thread_pool.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_async_timer.h>
#include <fluent-bit/flb_scheduler.h>

void flb_async_timer_destroy(struct flb_async_timer *timer)
{
    mk_list_del(&timer->_head);
    flb_coro_destroy(timer->coro);
    flb_free(timer);
}

void flb_async_timer_cleanup(struct flb_sched *sched)
{
    struct flb_async_timer *async_timer;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *destroy_list = &sched->async_timer_list_destroy;

    mk_list_foreach_safe(head, tmp, destroy_list) {
        async_timer = mk_list_entry(head, struct flb_async_timer, _head);
        mk_list_del(&async_timer->_head);
        flb_async_timer_destroy(async_timer);
    }
}

int flb_sched_out_async_timer_cb_create(struct flb_sched *sched, int type, int ms,
                                        struct flb_output_instance *o_ins,
                                        char *job_name,
                                        void (*async_cb)(struct flb_config *, void *),
                                        void *data, struct flb_sched_timer **out_timer)
{
    struct flb_async_timer_cb_data *timer_data;

    timer_data = flb_calloc(1, sizeof(struct flb_async_timer_cb_data));
    if (!timer_data) {
        return -1;
    }

    timer_data->is_threaded = o_ins->is_threaded;
    timer_data->plugin_alias = o_ins->alias;
    timer_data->job_name = job_name;
    timer_data->async_cb = async_cb;
    timer_data->data = data;

    return flb_sched_timer_cb_create(sched, type, ms, flb_out_async_sched_timer_cb, timer_data, NULL);
}

/* Used in engine flb_running_count */
int flb_async_timers_size(struct flb_config *config)
{
    int n = 0;
    int timers = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_output_instance *o_ins;

    timers = mk_list_size(&config->sched->async_timer_list);

    mk_list_foreach_safe(head, tmp, &config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (flb_output_is_threaded(o_ins) == FLB_TRUE) {
            n = flb_thread_pool_async_timers_size(o_ins);
            timers = timers + n;
        }
    }

    return timers;
}

void flb_async_timers_print(struct flb_sched *sched)
{ 
    struct flb_async_timer *async_timer;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *async_timer_list = &sched->async_timer_list;
    int n = mk_list_size(async_timer_list);
    if (n != 0) {
        /* get one coro for the job_name */
        mk_list_foreach_safe(head, tmp, async_timer_list) {
            async_timer = mk_list_entry(head, struct flb_async_timer, _head);
            if (async_timer != NULL) {
                flb_info("[task]   %s still running %d %s(s)",
                         async_timer->timer_data->plugin_alias, n, async_timer->timer_data->job_name);
                break;
            }
        }
    }
}

/* Used in engine flb_running_print */
void flb_async_timers_print_all(struct flb_config *config)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_output_instance *o_ins;

    flb_async_timers_print(config->sched);

    mk_list_foreach_safe(head, tmp, &config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (flb_output_is_threaded(o_ins) == FLB_TRUE) {
            flb_thread_pool_async_timers_print(o_ins);
        }
    }
}

int flb_thread_pool_async_timers_size(struct flb_output_instance *ins)
{
    int n;
    int size = 0;
    struct mk_list *head;
    struct flb_tp *tp = ins->tp;
    struct flb_tp_thread *th;
    struct flb_out_thread_instance *th_ins;

    mk_list_foreach(head, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        if (th->status != FLB_THREAD_POOL_RUNNING) {
            continue;
        }

        th_ins = th->params.data;

        pthread_mutex_lock(&th_ins->sched->async_timer_mutex);
        n = mk_list_size(&th_ins->sched->async_timer_list);
        pthread_mutex_unlock(&th_ins->sched->async_timer_mutex);
        size += n;
    }

    return size;
}

void flb_thread_pool_async_timers_print(struct flb_output_instance *ins)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tp *tp = ins->tp;
    struct flb_tp_thread *th;
    struct flb_out_thread_instance *th_ins;

    mk_list_foreach_safe(head, tmp, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        if (th->status != FLB_THREAD_POOL_RUNNING) {
            continue;
        }

        th_ins = th->params.data;
        pthread_mutex_lock(&th_ins->sched->async_timer_mutex);
        flb_async_timers_print(th_ins->sched);
        pthread_mutex_unlock(&th_ins->sched->async_timer_mutex);
    }
}
