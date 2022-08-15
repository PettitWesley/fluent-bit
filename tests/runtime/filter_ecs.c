/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

struct filter_test_result {
    char *expected_pattern;     /* string that must occur in output */
    int expected_pattern_index; /* which record to check for the pattern */
    int expected_records;       /* expected number of outputted records */
    int actual_records;         /* actual number of outputted records */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    struct filter_test_result *expected;
    char *result;

    expected = (struct filter_test_result *) data;
    result = (char *) record;

    if (expected->expected_pattern_index == expected->actual_records) {
        p = strstr(result, expected->expected_pattern);
        TEST_CHECK(p != NULL);

        if (!p) {
            flb_error("Expected to find: '%s' in result '%s'",
                    expected->expected_pattern, result);
        }
        /*
        * If you want to debug your test
        *
        * printf("Expect: '%s' in result '%s'\n", expected->expected_pattern, result);
        */
    }

    expected->actual_records++;

    flb_free(record);
    return 0;
}


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

struct str_list {
    size_t size; /* size of lists */
    int ignore_min_line_num; /* ignore line if the length is less than this value */
    char **lists; /* string lists */
};

/* Callback to check expected results */
static int cb_check_str_list(void *record, size_t size, void *data)
{
    char *p;
    char *out_line = record;
    int num = get_output_num();
    int count = 0;
    size_t i;
    struct str_list *l = (struct str_list *)data;

    if (!TEST_CHECK(out_line != NULL)) {
        TEST_MSG("out_line is NULL");
        return -1;
    }

    if (!TEST_CHECK(l != NULL)) {
        TEST_MSG("l is NULL");
        flb_free(out_line);
        return -1;
    }

    if (strlen(out_line) < l->ignore_min_line_num) {
        flb_free(out_line);
        return 0;
    }

    for (i=0; i<l->size; i++) {
        p = strstr(out_line, l->lists[i]);
        if (p != NULL) {
            count++;
        }
    }
    if(!TEST_CHECK(count != 0)) {
        TEST_MSG("%s is not matched", out_line);
    }
    set_output_num(num+count);

    flb_free(out_line);
    return 0;
}

static struct filter_test *filter_test_create(struct flb_lib_out_cb *data,
                                              char *tag)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    /* filter relies on the tag container 12 char short container ID */
    flb_input_set(ctx->flb, i_ffd, "tag", tag, NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "ecs", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_test_ecs_filter()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "testprefix-9581a69a761a");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "testprefix-",
                         "ADD", "$ClusterName.$TaskID.$ContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with metadata added */
    expected.expected_pattern = "cluster_name.example5-58ff-46c9-ae05-543f8example.mysql";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}


TEST_LIST = {

    {"flb_test_multiline_partial_message_concat_two_ids"  , flb_test_multiline_partial_message_concat_two_ids },
    {NULL, NULL}
};
