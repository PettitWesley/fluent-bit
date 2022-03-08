/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#include "ml_concat.h"

char *get_key(msgpack_object *map, char *check_for_key)
{
    int i;
    char *key_str = NULL;
    size_t key_str_size = 0;
    char *val_str = NULL;
    size_t val_str_size = 0;
    msgpack_object_kv *kv;
    msgpack_object  key;
    msgpack_object  val;
    int check_key = FLB_FALSE;

    kv = map.via.map.ptr;

    for(i=0; i < map_size; i++) {
        check_key = FLB_FALSE;

        key = (kv+i)->key;
        if (key.type == MSGPACK_OBJECT_BIN) {
            key_str  = (char *) key.via.bin.ptr;
            key_str_size = key.via.bin.size;
            check_key = FLB_TRUE;
        }
        if (key.type == MSGPACK_OBJECT_STR) {
            key_str  = (char *) key.via.str.ptr;
            key_str_size = key.via.str.size;
            check_key = FLB_TRUE;
        }

        if (check_key == FLB_TRUE) {
            if (strncmp(check_for_key, key_str, key_str_size) == 0) {
                val = (kv+i)->val;
                if (val.type == MSGPACK_OBJECT_BIN) {
                    val_str  = (char *) val.via.bin.ptr;
                    return val_str;
                }
                if (val.type == MSGPACK_OBJECT_STR) {
                    val_str  = (char *) val.via.str.ptr;
                    return val_str;
                }
            }
            return NULL;
        }
    }
    return NULL;
}

int is_partial(msgpack_object *map)
{
    char *partial_key_value;
    
    // TODO: config/constant
    partial_key_value = get_key(map, "partial_message");

    if (partial_key_value == NULL) {
        return FLB_FALSE;
    }

    // TODO: config/constant
    if (strncasecmp("true", val_str, 4) == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

struct split_message_packer *get_packer(struct mk_list packers, char *tag, 
                                        char *input_name, char *partial_id)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct split_message_packer *packer;
    int name_check;
    int tag_check;
    int id_check;


    mk_list_foreach_safe(head, tmp, packers) {
        packer = mk_list_entry(head, struct split_message_packer, _head);
        id_check = strcmp(packer->partial_id, partial_id);
        if (id_check != 0) {
            continue;
        }
        name_check = strcmp(packer->input_name, input_name);
        if (name_check != 0) {
            continue;
        }
        tag_check = strcmp(packer->tag, tag);
        if (tag_check == 0) {
            return packer;
        }
    }
}

struct split_message_packer *create_packer(char *tag, char *input_name, char *partial_id,
                                           msgpack_object *map, char *multiline_key_content,
                                           struct flb_time *tm;)
{
    struct split_message_packer *packer;
    flb_sds_t tmp;

    packer = flb_calloc(1, sizeof(struct split_message_packer));
    if (!packer) {
        flb_errno();
        return NULL;
    }

    tmp = flb_sds_create(input_name);
    if (!tmp) {
        flb_errno();
        flb_free(packer);
        return NULL;
    }
    packer->input_name = tmp;

    tmp = flb_sds_create(tag);
    if (!tmp) {
        flb_errno();
        split_message_packer_destroy(packer);
        return NULL;
    }
    packer->tag = tmp;

    tmp = flb_sds_create(partial_id);
    if (!tmp) {
        flb_errno();
        split_message_packer_destroy(packer);
        return NULL;
    }
    packer->partial_id = tmp;

    msgpack_sbuffer_init(&packer->mp_sbuf);
    msgpack_packer_init(&packer->mp_pck, &packer->mp_sbuf, msgpack_sbuffer_write);

    /* write all of the keys except the 
}

void split_message_packer_destroy(struct split_message_packer *packer)
{
    if (!packer) {
        return;
    }

    if (packer->buf) {
        flb_sds_destroy(packer->buf);
    }
    if (packer->tag) {
        flb_sds_destroy(packer->tag);
    }
    if (packer->input_name) {
        flb_sds_destroy(packer->input_name);
    }
    if (packer->partial_id) {
        flb_sds_destroy(packer->partial_id);
    }
    if (packer->mp_sbuf) {
        msgpack_sbuffer_destroy(&packer->mp_sbuf);
    }

    flb_free(packer);
}

