/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;

    expected = (char *) data;
    result = (char *) record;

    p = strstr(result, expected);
    TEST_CHECK(p != NULL);

    if (!p) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, result);
    }
    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    printf("Expect: '%s' in result '%s'", expected, result);

    flb_free(record);
    return 0;
}



static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
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
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "multiline", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    sleep(2);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_test_multiline_buffered()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "on",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"test_key\":\"test_value\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /*
goroutine 4 [running]:
panic(0x45cb40, 0x47ad70)
  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c
main.main.func1(0xc420024120)
  foo.go:6 +0x39 fp=0xc42003f7d8 sp=0xc42003f7b8 pc=0x451339
runtime.goexit()
  /usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003f7e0 sp=0xc42003f7d8 pc=0x44b4d1
created by main.main
  foo.go:5 +0x58
    */

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

TEST_LIST = {
    {"multiline_buffered"            , flb_test_multiline_buffered },
    {NULL, NULL}
};