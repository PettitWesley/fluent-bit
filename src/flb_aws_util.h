/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifdef FLB_HAVE_AWS

#ifndef FLB_AWS_CREDENTIALS_H
#define FLB_AWS_CREDENTIALS_H

#define FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER           "X-aws-ec2-metadata-token-ttl-seconds"
#define FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN       36

#define FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL       "21600"
#define FLB_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN   5

#define FLB_AWS_IMDS_V2_TOKEN_TTL                  21600

#define FLB_AWS_IMDS_V2_HOST                       "169.254.169.254"
#define FLB_AWS_IMDS_V2_TOKEN_PATH                 "/latest/api/token"

/*
 * Get an IMDSv2 token
 */
static int get_ec2_token(struct flb_upstream *upstream, flb_sds_t *token, unsigned int *token_len);

/*
 * Get data at an IMDSv2 path
 */
static int get_metadata(struct flb_upstream *upstream, char *metadata_path,
                        flb_sds_t *metadata, unsigned int *metadata_len,
                        flb_sds_t token, unsigned int token_len);

#endif
#endif /* FLB_HAVE_AWS */
