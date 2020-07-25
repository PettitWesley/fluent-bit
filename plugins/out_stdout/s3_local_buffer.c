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

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output_plugin.h>
#include <monkey/mk_core/mk_list.h>

#include "s3_local_buffer.h"



/*
 * Stores data in the local file system
 * Subsequent data with the same 'key' will be stored to the same local 'chunk'
 */
int buffer_data(struct local_buffer *store, char *key)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct chunk *c = NULL;
    struct chunk *tmp_chunk;
    flb_sds_t path;

    mk_list_foreach_safe(head, tmp, &store->chunks) {
        tmp_chunk = mk_list_entry(head, struct chunk, _head);
        if (strcmp(tmp_chunk->key, key) == 0) {
            c = tmp_chunk;
            break;
        }
    }

    if (c == NULL) {
        /* create a new chunk */
        c = flb_calloc(1, sizeof(struct chunk));
        if (!c) {
            flb_errno();
            return -1;
        }
        c->key = flb_sds_create(key);
        if (!c->key) {
            flb_errno();
            flb_free(c);
            return -1;
        }
    }

}

/*
 * Returns the chunk associated with the given key
 */
struct chunk *get_chunk(struct local_buffer *store, char *key);

/*
 * Reads data from the chunk in the local buffer
 */
char *read_chunk(struct chunk *c);
