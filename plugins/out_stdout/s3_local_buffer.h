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

struct chunk {
    flb_sds_t key;
    flb_sds_t file_path;
    size_t size;

    struct mk_list _head;
};

struct local_buffer {
    char *dir;
    struct flb_output_instance *ins;

    struct mk_list chunks;
};

/*
 * Stores data in the local file system
 * Subsequent data with the same 'key' will be stored to the same local 'chunk'
 */
int buffer_data(struct local_buffer *store, char *key);

/*
 * Returns the chunk associated with the given key
 */
struct chunk *get_chunk(struct local_buffer *store, char *key);

/*
 * Reads data from the chunk in the local buffer
 */
char *read_chunk(struct chunk *c);

#endif
