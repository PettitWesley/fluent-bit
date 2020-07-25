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
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#include "s3_local_buffer.h"


void destroy_chunk(struct chunk *c)
{
    if (!c) {
        return;
    }
    if (c->key) {
        flb_sds_destroy(c->key);
    }
    if (c->file_path) {
        flb_sds_destroy(c->file_path);
    }
    flb_free(c);
}

/*
 * Recursively creates directories needed for 'file'
 */
static int chunk_mkdir(const char *file) {
    char tmp[PATH_MAX];
    char *p = NULL;
    int ret;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",file);
    len = strlen(tmp);
    if(tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    for(p = tmp + 1; *p; p++) {
        if(*p == '/') {
            *p = 0;
            ret = mkdir(tmp, S_IRWXU);
            if (ret < 0 && errno != EEXIST) {
                flb_errno();
                return -1;
            }
            *p = '/';
        }
    }

    return 0;
}

static int append_data(struct local_buffer *store, char *path,
                       char *data, size_t bytes)
{
    FILE *f;
    size_t written;
    f = fopen(path , "a" );
    if (!f) {
        return -1;
    }
    written = fwrite(data, 1, bytes, f);
    if (written < bytes) {
        flb_plg_error(store->ins, "Failed to write %d bytes to local buffer %s",
                      bytes - written, path);
        flb_errno();
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/*
 * Stores data in the local file system
 * Subsequent data with the same 'key' will be stored to the same local 'chunk'
 */
int buffer_data(struct local_buffer *store, char *key, char *data, size_t bytes)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct chunk *c = NULL;
    struct chunk *tmp_chunk;
    int ret;
    flb_sds_t path;
    flb_sds_t tmp_sds;

    mk_list_foreach_safe(head, tmp, &store->chunks) {
        tmp_chunk = mk_list_entry(head, struct chunk, _head);
        if (strcmp(tmp_chunk->key, key) == 0) {
            c = tmp_chunk;
            break;
        }
    }

    if (c == NULL) {
        /* create a new chunk */
        flb_plg_debug(store->ins, "Creating new local buffer for key %s", key);
        c = flb_calloc(1, sizeof(struct chunk));
        if (!c) {
            flb_errno();
            return -1;
        }
        c->create_time = time(NULL);
        c->key = flb_sds_create(key);
        if (!c->key) {
            flb_errno();
            destroy_chunk(c);
            return -1;
        }
        path = flb_sds_create_size(strlen(store->dir) + strlen(key));
        if (!path) {
            flb_errno();
        }
        tmp_sds = flb_sds_printf(&path, "%s/%s", store->dir, key);
        if (!tmp_sds) {
            flb_errno();
            destroy_chunk(c);
            flb_sds_destroy(path);
        }
        path = tmp_sds;
        c->file_path = path;
        ret = chunk_mkdir(path);
        if (ret < 0) {
            flb_plg_error(store->ins, "Failed to create directories in path %s", path);
            destroy_chunk(c);
            return ret;
        }
        mk_list_add(&c->_head, &store->chunks);
    }

    ret = append_data(store, c->file_path, data, bytes);
    if (ret < 0) {
        flb_plg_error(store->ins, "Failed to buffer data");
        return -1;
    }
    flb_plg_debug(store->ins, "Buffered %d bytes", bytes);
    return 0;
}



/*
 * Returns the chunk associated with the given key
 */
struct chunk *get_chunk(struct local_buffer *store, char *key);

/*
 * Reads data from the chunk in the local buffer
 */
char *read_chunk(struct chunk *c);
