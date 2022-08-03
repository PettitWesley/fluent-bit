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

#ifndef FLB_FILTER_ECS_H
#define FLB_FILTER_ECS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

#define FLB_ECS_FILTER_HOST                       "127.0.0.1"
#define FLB_ECS_FILTER_PORT                       "51678"
#define FLB_ECS_FILTER_CLUSTER_PATH               "/v1/metadata"
#define FLB_ECS_FILTER_TASKS_PATH                 "/v1/tasks"

struct flb_ecs_metadata {
    flb_sds_t key;
    flb_sds_t template;
    struct flb_record_accessor ra;

    struct mk_list _head;
};


struct flb_filter_ecs {
    /* upstream connection to ECS Agent */
    struct flb_upstream *ecs_upstream;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;

    struct mk_list metadata_keys;
};

#endif
