/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_s3_local_buffer.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_util.h>

#include "flb_tests_internal.h"

#define BUFFER_DIRECTORY FLB_TESTS_DATA_PATH "data/s3_local_buffer/"
#define PLUGIN_NAME "s3_plugin"
#define TEST_DATA "I love Fluent Bit"
#define KEY_1 "key1"
#define KEY_2 "key2"
#define KEY_3 "key3"

static void check_chunk(struct flb_local_chunk *chunk, char *tag, char *data)
{
    char *buffered_data = NULL;
    size_t buffer_size;
    int ret;
    /* Ensure data retreived is same as that which was stored. */
    if (chunk->tag == tag){
        ret = flb_read_file(chunk->file_path, &buffered_data, &buffer_size);
        TEST_CHECK(ret == 0);
        TEST_CHECK(strcmp(buffered_data, data) == 0);
    }

}

static void test_flb_buffer_put_create_chunk()
{
    int ret;
    struct flb_local_buffer *store = flb_calloc(1, sizeof(struct flb_local_buffer));
    struct flb_output_instance *out = flb_calloc(1, sizeof(struct flb_output_instance));

    store->dir = BUFFER_DIRECTORY;
    memcpy(out->name, PLUGIN_NAME, strlen(PLUGIN_NAME));
    store->ins = out;
    mk_list_init(&store->chunks);
    TEST_CHECK(mk_list_size(&store->chunks) == 0);

    char *data = TEST_DATA;
    char *key1 = KEY_1 ;
    size_t data_len = strlen(data);
    struct flb_local_chunk *chunk;

    /* No local chunk suitable for this data has been created yet,
     * hence chunk should be NULL.
     */
    chunk = flb_chunk_get(store, key1);
    TEST_CHECK(chunk == NULL);
    ret = flb_buffer_put(store, chunk, key1, data, data_len);
    TEST_CHECK(ret == 0);

    /* Ensure that the data stored and retrieved from the chunk is the same. */
    chunk = flb_chunk_get(store, key1);
    check_chunk(chunk, key1, data);

    ret = flb_remove_chunk_files(chunk);
    TEST_CHECK(ret == 0);
    flb_chunk_destroy(chunk);
    flb_free(out);
    flb_free(store);
}

static void test_flb_buffer_put_valid_chunk()
{
    int ret;
    struct flb_local_buffer *store = flb_calloc(1, sizeof(struct flb_local_buffer));
    struct flb_output_instance *out = flb_calloc(1, sizeof(struct flb_output_instance));

    store->dir = BUFFER_DIRECTORY;
    memcpy(out->name, PLUGIN_NAME, strlen(PLUGIN_NAME));
    store->ins = out;
    mk_list_init(&store->chunks);
    TEST_CHECK(mk_list_size(&store->chunks) == 0);

    char *data = TEST_DATA;
    char *key2 = KEY_2;
    size_t data_len = strlen(data);
    struct flb_local_chunk *chunk;

    /* No local chunk suitable for this data has been created yet,
     * hence chunk should be NULL.
     */
    chunk = flb_chunk_get(store, key2);
    TEST_CHECK(chunk == NULL);

    ret = flb_buffer_put(store, chunk, key2, data, data_len);
    TEST_CHECK(ret == 0);

    /* A new chunk associated with key2 was created in the above statement,
     * hence this time, chunk should not be NULL.
     */
    chunk = flb_chunk_get(store,key2);
    TEST_CHECK(chunk != NULL);

    chunk = flb_chunk_get(store, key2);
    check_chunk(chunk, key2, data);

    ret = flb_remove_chunk_files(chunk);
    TEST_CHECK(ret == 0);
    flb_chunk_destroy(chunk);
    flb_free(out);
    flb_free(store);
}

static void test_flb_init_local_buffer()
{
    int ret;
    char *data = TEST_DATA;
    char *key3 = KEY_3;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_local_chunk *chunk;
    struct flb_local_buffer *store = flb_calloc(1,sizeof(struct flb_local_buffer));
    struct flb_output_instance *out = flb_calloc(1,sizeof(struct flb_output_instance));
    struct flb_local_buffer *new_store = flb_calloc(1,
                                                    sizeof(struct flb_local_buffer));
    struct flb_output_instance *new_out= flb_calloc(1,
                                                    sizeof(struct flb_output_instance));

    store->dir = BUFFER_DIRECTORY;
    memcpy(out->name, PLUGIN_NAME, strlen(PLUGIN_NAME));
    store->ins = out;
    mk_list_init(&store->chunks);
    TEST_CHECK(mk_list_size(&store->chunks) == 0);

    new_store->dir = BUFFER_DIRECTORY;
    memcpy(new_out->name, PLUGIN_NAME, strlen(PLUGIN_NAME));
    new_store->ins = new_out;
    mk_list_init(&new_store->chunks);
    TEST_CHECK(mk_list_size(&new_store->chunks) == 0);

    chunk = flb_chunk_get(store, key3);
    TEST_CHECK(chunk == NULL);
    ret = flb_buffer_put(store, chunk, key3, data, strlen(data));
    TEST_CHECK(ret == 0);
    ret = flb_init_local_buffer(new_store);
    TEST_CHECK(ret == 0);

    chunk = flb_chunk_get(new_store, key3);
    check_chunk(chunk, key3, data);

    ret = flb_remove_chunk_files(chunk);
    TEST_CHECK(ret == 0);
    flb_chunk_destroy(chunk);
    flb_free(out);
    flb_free(store);
    flb_free(new_out);
    flb_free(new_store);
}


TEST_LIST = {
    { "flb_buffer_put_create_chunk" , test_flb_buffer_put_create_chunk},
    { "flb_buffer_put_valid_chunk" , test_flb_buffer_put_valid_chunk},
    {"flb_buffer_init_local_buffer", test_flb_init_local_buffer},
    { 0 }
};
