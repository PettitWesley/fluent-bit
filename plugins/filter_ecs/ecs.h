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
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

#define FLB_ECS_FILTER_HOST                       "127.0.0.1"
#define FLB_ECS_FILTER_PORT                       51678
#define FLB_ECS_FILTER_CLUSTER_PATH               "/v1/metadata"
#define FLB_ECS_FILTER_TASK_PATH_FORMAT           "/v1/tasks?dockerid=%s"

/*
 * Kubernetes recommends not running more than 110 pods per node
 * In ECS, the number of tasks per instance will vary considerably
 * But this should be a very safe starting size for the table
 * Since we use the TTL hash table there is no max size. 
 */
#define FLB_ECS_FILTER_HASH_TABLE_SIZE 100


struct flb_ecs_metadata_key {
    flb_sds_t key;
    flb_sds_t template;
    struct flb_record_accessor *ra;

    struct mk_list _head;
};

struct flb_ecs_metadata_buffer {
    char *buf;
    size_t size;

    msgpack_unpacked unpacked;
    msgpack_object obj;
};

struct flb_ecs_cluster_metadata {
    flb_sds_t cluster_name;
    flb_sds_t container_instance_arn;
    flb_sds_t container_instance_id;
    flb_sds_t ecs_agent_version;
};


struct flb_filter_ecs {
    /* upstream connection to ECS Agent */
    struct flb_upstream *ecs_upstream;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;

    struct mk_list metadata_keys;
    int metadata_keys_len;

    struct flb_ecs_cluster_metadata cluster_metadata;
    int has_cluster_metadata;

    /* 
     * Maps 12 char container short ID to metadata buffer
     */
    struct flb_hash *container_hash_table;

    int ecs_meta_cache_ttl;
};

#endif
