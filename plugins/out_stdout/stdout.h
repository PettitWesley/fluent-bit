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

#ifndef FLB_OUT_STDOUT
#define FLB_OUT_STDOUT

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

/* Upload data to S3 in 5MB chunks */
#define CHUNKED_UPLOAD_SIZE 5000000

struct upload_chunk {
    flb_sds_t s3_key;
    size_t size;
    int upload_in_progress;

    struct mk_list _head;
}

struct flb_stdout {
    char *bucket;
    char *region;
    char *prefix;
    char *time_key;
    char *endpoint;
    int free_endpoint;

    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    /* tls instances can't be re-used; aws provider requires a separate one */
    struct flb_tls provider_tls;
    /* one for the standard chain provider, one for sts assume role */
    struct flb_tls sts_provider_tls;
    struct flb_tls client_tls;

    struct flb_aws_client *s3_client;
    int json_date_format;
    flb_sds_t json_date_key;

    struct mk_list upload_chunks;

    struct flb_output_instance *ins;
};

#endif
