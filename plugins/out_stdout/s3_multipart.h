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

#ifndef FLB_OUT_STDOUT_S3_MULTIPART
#define FLB_OUT_STDOUT_S3_MULTIPART

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_util.h>

#define MULTIPART_UPLOAD_STATE_NOT_CREATED   0
#define MULTIPART_UPLOAD_STATE_CREATED       1
#define MULTIPART_UPLOAD_STATE_COMPLETED     2

#include "stdout.h"

struct multipart_upload {
    flb_sds_t s3_key;
    flb_sds_t upload_id;
    int upload_state;

    /*
     * maximum of 10,000 parts in an upload, for each we need to store mapping
     * of Part Number to ETag
     */
    flb_sds_t *etags[10000];
    int part_number;
};

int upload_part(struct flb_stdout *ctx, struct multipart_upload *m_upload,
                char *body, size_t body_size);

int create_multipart_upload(struct flb_stdout *ctx,
                            struct multipart_upload *m_upload);

#endif
