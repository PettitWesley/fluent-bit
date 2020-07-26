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

#ifndef FLB_OUT_S3_LOCAL_BUFFER_H
#define FLB_OUT_S3_LOCAL_BUFFER_H

struct local_chunk {
    flb_sds_t key;
    flb_sds_t file_path;
    size_t size;
    time_t create_time;

    struct mk_list _head;
};

struct local_buffer {
    char *dir;
    struct flb_output_instance *ins;

    struct mk_list chunks;
};

/*
 * "Initializes" the local buffer from the file system
 * Reads buffer directory and finds any existing files
 * This ensures the plugin will still send data even if FB is restarted
 */
// int init_from_file_system(struct local_buffer *store);

/*
 * Stores data in the local file system
 * 'c' should be NULL if no local chunk suitable for this data has been created yet
 */
 int buffer_data(struct local_buffer *store, struct local_chunk *c,
                 char *key, char *data, size_t bytes)

/*
 * Returns the chunk associated with the given key
 */
struct local_chunk *get_chunk(struct local_buffer *store, char *key);


void destroy_chunk(struct local_chunk *c);

#endif
