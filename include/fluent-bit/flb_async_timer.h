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

#ifndef FLB_ASYNC_TIMER_H
#define FLB_ASYNC_TIMER_H

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_async_timer.h>
#include <fluent-bit/flb_thread_pool.h>
#include <fluent-bit/flb_output_thread.h>


void flb_async_timer_destroy(struct flb_async_timer *timer);
void flb_async_timer_cleanup(struct flb_sched *sched);
void flb_output_async_timer_cleanup(struct flb_config *config);
int flb_sched_out_async_timer_cb_create(struct flb_sched *sched, int type, int ms,
                                        struct flb_output_instance *o_ins,
                                        char *job_name,
                                        void (*async_cb)(struct flb_config *, void *),
                                        void *data, struct flb_sched_timer **out_timer);
void flb_async_timers_print_all(struct flb_config *config);
void flb_async_timers_print(struct flb_sched *sched);
int flb_async_timers_size(struct flb_config *config);
int flb_thread_pool_async_timers_size(struct flb_output_instance *ins);
void flb_thread_pool_async_timers_print(struct flb_output_instance *ins);

/*
 * stores timer coros on the async_timer_list, if the output uses them
 */
struct flb_async_timer {
    struct flb_config *config;         /* FLB context        */
    struct flb_async_timer_cb_data *timer_data; /* callback info */
    struct flb_coro *coro;             /* parent coro addr   */
    struct mk_list _head;              /* Link to async_timer_list */
};

/*
 * If the output uses timer coros, then this is used as the callback data
 * passed to flb_sched_timer_cb_create
 */
struct flb_async_timer_cb_data {
    int is_threaded; /* track on engine sched vs on worker sched */
    char *plugin_alias; /* used on engine shutdown, print pending "custom" jobs */
    char *job_name; /* used on engine shutdown, print pending "custom" jobs */
    void (*async_cb) (struct flb_config *config, void *data); /* call this output callback in the coro */
    void *data; /* opaque data to pass to the above cb */
};

extern FLB_TLS_DEFINE(struct flb_async_timer, async_timer_coro_params);


/* The coro callee callback for async timer coros */
static FLB_INLINE void out_async_timer_cb(void)
{
    struct flb_coro *coro;
    struct flb_async_timer *async_timer;
    struct flb_sched *sched;


    async_timer = (struct flb_async_timer *) FLB_TLS_GET(async_timer_coro_params);
    if (!async_timer) {
        flb_error("[output] no async timer coro params defined, unexpected");
        return;
    }

    coro = async_timer->coro;

    /* Run the callback provided by the output plugin */
    async_timer->timer_data->async_cb(async_timer->config, async_timer->timer_data->data);

    /* move coro to destroy queue */
    if (async_timer->timer_data->is_threaded == FLB_TRUE) {
        sched = flb_sched_ctx_get();
        pthread_mutex_lock(&sched->async_timer_mutex);
        mk_list_del(&async_timer->_head);
        mk_list_add(&async_timer->_head, &sched->async_timer_list_destroy);
        pthread_mutex_unlock(&sched->async_timer_mutex);
    }
    else {
        mk_list_del(&async_timer->_head);
        sched = async_timer->config->sched;
        mk_list_add(&async_timer->_head, &sched->async_timer_list_destroy);
    }

    /* timer coro is complete; yield back to caller/control code */
    flb_coro_yield(coro, FLB_TRUE);
}

/* 
 * If the output uses scheduled timers with coroutines,
 * this function is used as the callback for flb_sched_timer_cb_create
 */
static FLB_INLINE
void flb_out_async_sched_timer_cb(struct flb_config *config, void *data)
{
    size_t stack_size;
    struct flb_coro *coro;
    struct flb_async_timer *async_timer;
    struct flb_async_timer *timer_thread_key;
    struct flb_async_timer_cb_data *ctx = (struct flb_async_timer_cb_data *) data;
    struct flb_sched *sched;

    /* Custom output coroutine info */
    async_timer = (struct flb_async_timer*) flb_calloc(1, sizeof(struct flb_async_timer));
    if (!async_timer) {
        flb_errno();
        return;
    }

    /* Create a new co-routine */
    coro = flb_coro_create(async_timer);
    if (!coro) {
        flb_free(async_timer);
        return;
    }

    async_timer->config = config;
    async_timer->coro   = coro;
    async_timer->timer_data = ctx;

    coro->callee = co_create(config->coro_stack_size,
                             out_async_timer_cb, &stack_size);

    if (coro->callee == NULL) {
        flb_coro_destroy(coro);
        flb_free(async_timer);
        return;
    }

#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = \
        VALGRIND_STACK_REGISTER(coro->callee, ((char *) coro->callee) + stack_size);
#endif

    if (ctx->is_threaded == FLB_TRUE) {
        sched = flb_sched_ctx_get();
        pthread_mutex_lock(&sched->async_timer_mutex);
        mk_list_add(&async_timer->_head, &sched->async_timer_list);
        pthread_mutex_unlock(&sched->async_timer_mutex);
    }
    else {
        mk_list_add(&async_timer->_head, &config->sched->async_timer_list);
    }

    /* Same struct used in async_timer_list and in the pthread key,
     * Unique memory needed since these are freed separately
     */
    timer_thread_key = (struct flb_async_timer *) FLB_TLS_GET(async_timer_coro_params);
    if (!timer_thread_key) {
        timer_thread_key = (struct flb_async_timer *) flb_calloc(1, sizeof(struct flb_async_timer));
        if (!timer_thread_key) {
            flb_errno();
            return;
        }
    }

    /* copy to thread local storage */
    timer_thread_key->coro = coro;
    timer_thread_key->timer_data = async_timer->timer_data;
    timer_thread_key->config = config;

    FLB_TLS_SET(async_timer_coro_params, timer_thread_key);
    coro->caller = co_active();
    flb_coro_resume(coro);
    return;
}



#endif
