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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <ctype.h>
#include <msgpack.h>

#include "s3.h"

#define COMPLETE_MULTIPART_UPLOAD_BASE_LEN 100
#define COMPLETE_MULTIPART_UPLOAD_PART_LEN 124

flb_sds_t get_etag(char *response, size_t size);

static inline int try_to_write(char *buf, int *off, size_t left,
                               const char *str, size_t str_len)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        return FLB_FALSE;
    }
    memcpy(buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}

/*
 * https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
 */
static int complete_multipart_upload_payload(struct flb_s3 *ctx,
                                             struct multipart_upload *m_upload,
                                             char **out_buf, size_t *out_size)
{
    char *buf;
    int i;
    int offset = 0;
    flb_sds_t etag;
    size_t size = COMPLETE_MULTIPART_UPLOAD_BASE_LEN;
    char part_num[7];
    int last_part_num;

    /* part_number on the upload will be set to next expected part number */
    last_part_num = m_upload->part_number - 1;

    size = size + (COMPLETE_MULTIPART_UPLOAD_PART_LEN * last_part_num);

    buf = flb_malloc(size + 1);
    if (!buf) {
        flb_errno();
        return -1;
    }

    if (!try_to_write(buf, &offset, size,
                      "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">", 73)) {
        goto error;
    }

    for (i = 0; i < last_part_num; i++) {
        etag = m_upload->etags[i];
        if (!try_to_write(buf, &offset, size,
                          "<Part><ETag>", 12)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          etag, 0)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          "</ETag><PartNumber>", 19)) {
            goto error;
        }

        if (!sprintf(part_num, "%d", i + 1)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          part_num, 0)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          "</PartNumber></Part>", 20)) {
            goto error;
        }
    }

    if (!try_to_write(buf, &offset, size,
                      "</CompleteMultipartUpload>", 26)) {
        goto error;
    }

    buf[offset] = '\0';

    *out_buf = buf;
    *out_size = offset;
    return 0;

error:
    flb_free(buf);
    flb_plg_error(ctx->ins, "Failed to construct CompleteMultipartUpload "
                  "request body");
    return -1;
}

int complete_multipart_upload(struct flb_s3 *ctx,
                              struct multipart_upload *m_upload)
{
    char *body;
    size_t size;
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    int ret;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;

    flb_info("[complete_multipart_upload] ID=%s", m_upload->upload_id);

    uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 11 +
                              flb_sds_len(m_upload->upload_id));
    if (!uri) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&uri, "%s?uploadId=%s", m_upload->s3_key,
                         m_upload->upload_id);
    if (!tmp) {
        flb_sds_destroy(uri);
        return -1;
    }
    uri = tmp;

    ret = complete_multipart_upload_payload(ctx, m_upload, &body, &size);
    if (ret < 0) {
        flb_sds_destroy(uri);
        return -1;
    }

    flb_info("Raw request: %s", body);

    s3_client = ctx->s3_client;
    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_POST,
                                          uri, body, size,
                                          NULL, 0);
    flb_sds_destroy(uri);
    flb_free(body);
    if (c) {
        flb_plg_debug(ctx->ins, "CompleteMultipartUpload http status=%d",
                      c->resp.status);
        if (c->resp.status == 200) {
            flb_plg_info(ctx->ins, "Successfully completed multipart upload "
                         "for %s, UploadId=%s", m_upload->s3_key,
                         m_upload->upload_id);
            flb_http_client_destroy(c);
            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "CompleteMultipartUpload", ctx->ins);
        if (c->resp.data != NULL) {
            flb_plg_debug(ctx->ins, "Raw CompleteMultipartUpload response: %s",
                          c->resp.data);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "CompleteMultipartUpload request failed");
    return -1;
}


int create_multipart_upload(struct flb_s3 *ctx,
                            struct multipart_upload *m_upload)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;

    flb_info("[create_multipart_upload] ID=%s", m_upload->upload_id);

    uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 8);
    if (!uri) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&uri, "%s?uploads=", m_upload->s3_key);
    if (!tmp) {
        flb_sds_destroy(uri);
        return -1;
    }
    uri = tmp;

    s3_client = ctx->s3_client;
    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_POST,
                                          uri, NULL, 0, NULL, 0);
    flb_sds_destroy(uri);
    if (c) {
        flb_plg_debug(ctx->ins, "CreateMultipartUpload http status=%d",
                      c->resp.status);
        if (c->resp.status == 200) {
            tmp = flb_xml_get_val(c->resp.payload, c->resp.payload_size,
                                  "<UploadId>");
            if (!tmp) {
                flb_plg_error(ctx->ins, "Could not find upload ID in "
                              "CreateMultipartUpload response");
                flb_plg_debug(ctx->ins, "Raw CreateMultipartUpload response: %s",
                              c->resp.data);
                flb_http_client_destroy(c);
                return -1;
            }
            m_upload->upload_id = tmp;
            flb_plg_info(ctx->ins, "Successfully initiated multipart upload "
                         "for %s, UploadId=%s", m_upload->s3_key,
                         m_upload->upload_id);
            flb_http_client_destroy(c);
            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "CreateMultipartUpload", ctx->ins);
        if (c->resp.data != NULL) {
            flb_plg_debug(ctx->ins, "Raw CreateMultipartUpload response: %s",
                          c->resp.data);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "CreateMultipartUpload request failed");
    return -1;
}

/* gets the ETag value from response headers */
flb_sds_t get_etag(char *response, size_t size)
{
    char *tmp;
    int start;
    int end;
    int len;
    int i = 0;
    flb_sds_t etag;
    tmp = strstr(response, "ETag:");
    if (!tmp) {
        return NULL;
    }
    i = tmp - response;

    /* advance to end of ETag key */
    i += 5;

    /* advance across any whitespace and the opening quote */
    while (i < size && (response[i] == '\"' || isspace(response[i]) != 0)) {
        i++;
    }
    start = i;
    /* advance until we hit whitespace or the end quote */
    while (i < size && (response[i] != '\"' && isspace(response[i]) == 0)) {
        i++;
    }
    end = i;
    len = end - start;

    etag = flb_sds_create_len(response + start, len);
    if (!etag) {
        flb_errno();
        return NULL;
    }

    return etag;
}

int upload_part(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                char *body, size_t body_size)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;

    flb_info("[upload_part] ID=%s", m_upload->upload_id);

    uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 8);
    if (!uri) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&uri, "%s?partNumber=%d&uploadId=%s",
                         m_upload->s3_key, m_upload->part_number,
                         m_upload->upload_id);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(uri);
        return -1;
    }
    uri = tmp;

    s3_client = ctx->s3_client;
    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                          uri, body, body_size,
                                          NULL, 0);
    flb_sds_destroy(uri);
    if (c) {
        flb_plg_debug(ctx->ins, "UploadPart http status=%d",
                      c->resp.status);
        if (c->resp.status == 200) {
            tmp = get_etag(c->resp.data, c->resp.data_size);
            if (!tmp) {
                flb_plg_error(ctx->ins, "Could not find ETag in "
                              "UploadPart response");
                flb_plg_debug(ctx->ins, "Raw UploadPart response: %s",
                              c->resp.data);
                flb_http_client_destroy(c);
                return -1;
            }
            m_upload->etags[m_upload->part_number - 1] = tmp;
            flb_plg_info(ctx->ins, "Successfully uploaded part #%d "
                         "for %s, UploadId=%s, ETag=%s", m_upload->part_number,
                         m_upload->s3_key, m_upload->upload_id, tmp);
            flb_http_client_destroy(c);
            /* track how many bytes are have gone toward this upload */
            m_upload->bytes += body_size;
            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "UploadPart", ctx->ins);
        if (c->resp.data != NULL) {
            flb_plg_debug(ctx->ins, "Raw UploadPart response: %s",
                          c->resp.data);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "UploadPart request failed");
    return -1;
}
