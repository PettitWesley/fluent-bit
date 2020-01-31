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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

#include <jsmn/jsmn.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define AWS_IMDS_ROLE_PATH      "/latest/meta-data/iam/security-credentials/"
#define AWS_IMDS_ROLE_PATH_LEN  43

struct aws_credentials_provider_ec2;
static int get_creds_ec2(struct aws_credentials_provider_ec2 *implementation);
static int ec2_credentials_request(struct aws_credentials_provider_ec2
                                   *implementation, char *cred_path);

/* EC2 IMDS Provider */

/*
 * A provider that obtains credentials from EC2 IMDS.
 */
struct aws_credentials_provider_ec2 {
    struct aws_credentials *creds;
    time_t next_refresh;

    /* upstream connection to IMDS */
    struct aws_http_client *client;

    /*
     * Currently, we only support IMDSv1. Once improvements in the core net IO
     * library is made. We will support v2 and v1 and use whichever is available.
     */
    int imds_version;

    /* IMDSv2 Token */
    flb_sds_t imds_v2_token;
    size_t imds_v2_token_len;
    time_t token_refresh;
};

struct aws_credentials *get_credentials_fn_ec2(struct aws_credentials_provider
                                               *provider)
{
    struct aws_credentials *creds;
    int ret;
    int refresh = FLB_FALSE;
    struct aws_credentials_provider_ec2 *implementation = provider->
                                                          implementation;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "EC2 provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        ret = get_creds_ec2(implementation);
        if (ret < 0) {
            return NULL;
        }
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        flb_errno();
        return NULL;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        flb_errno();
        aws_credentials_destroy(creds);
        return NULL;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        aws_credentials_destroy(creds);
        return NULL;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            flb_errno();
            aws_credentials_destroy(creds);
            return NULL;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;
}

int refresh_fn_ec2(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_ec2 *implementation = provider->
                                                          implementation;
    flb_debug("[aws_credentials] Refresh called on the EC2 IMDS provider");
    return get_creds_ec2(implementation);
}

void destroy_fn_ec2(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_ec2 *implementation = provider->
                                                          implementation;

    if (implementation) {
        if (implementation->creds) {
            aws_credentials_destroy(implementation->creds);
        }

        if (implementation->client) {
            aws_client_destroy(implementation->client);
        }

        if (implementation->imds_v2_token) {
            flb_sds_destroy(implementation->imds_v2_token);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct aws_credentials_provider_vtable ec2_provider_vtable = {
    .get_credentials = get_credentials_fn_ec2,
    .refresh = refresh_fn_ec2,
    .destroy = destroy_fn_ec2,
};

struct aws_credentials_provider *new_ec2_provider(struct flb_config *config,
                                                  struct
                                                  aws_http_client_generator
                                                  *generator)
{
    struct aws_credentials_provider_ec2 *implementation;
    struct aws_credentials_provider *provider;
    struct flb_upstream *upstream;

    provider = flb_calloc(1, sizeof(struct aws_credentials_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct aws_credentials_provider_ec2));

    if (!implementation) {
        flb_free(provider);
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &ec2_provider_vtable;
    provider->implementation = implementation;

    implementation->imds_version = 1;

    upstream = flb_upstream_create(config, AWS_IMDS_V2_HOST, 80,
                                   FLB_IO_TCP, NULL);
    if (!upstream) {
        aws_provider_destroy(provider);
        flb_error("[aws_credentials] EC2 IMDS: connection initialization "
                  "error");
        return NULL;
    }

    implementation->client = generator->new();
    if (!implementation->client) {
        aws_provider_destroy(provider);
        flb_upstream_destroy(upstream);
        flb_error("[aws_credentials] EC2 IMDS: client creation error");
        return NULL;
    }
    implementation->client->name = "ec2_imds_provider_client";
    implementation->client->has_auth = FLB_FALSE;
    implementation->client->provider = NULL;
    implementation->client->region = NULL;
    implementation->client->service = NULL;
    implementation->client->port = 80;
    implementation->client->flags = 0;
    implementation->client->proxy = NULL;
    implementation->client->upstream = upstream;

    return provider;
}

/* Requests creds from IMDSv1 and sets them on the provider */
static int get_creds_ec2(struct aws_credentials_provider_ec2 *implementation)
{
    int ret;
    flb_sds_t instance_role;
    size_t instance_role_len;
    char *cred_path;
    size_t cred_path_size;

    flb_debug("[aws_credentials] requesting credentials from EC2 IMDS");

    if (implementation->imds_version != 1) {
        if (!implementation->imds_v2_token ||
            (time(NULL) > implementation->token_refresh)) {
            flb_debug("[aws_credentials] requesting a new IMDSv2 token");

            /* free existing token */
            if (implementation->imds_v2_token) {
                flb_sds_destroy(implementation->imds_v2_token);
                implementation->imds_v2_token = NULL;
            }

            ret = get_ec2_token(implementation->client,
                                &implementation->imds_v2_token,
                                &implementation->imds_v2_token_len);

            if (ret == 0) {
                implementation->token_refresh = time(NULL)
                                                + AWS_IMDS_V2_TOKEN_TTL
                                                - FLB_AWS_REFRESH_WINDOW;
                /* v2 is available */
                implementation->imds_version = 2;
                flb_debug("[aws_credentials] IMDSv2 is available; will use it "
                          "from now on");
            } else {
                /*
                 * If the token request fails, we try IMDSv1.
                 * V1 is exactly the same, the token is just not required.
                 * Setting the token length to zero tells our code to use V1.
                 */
                 implementation->imds_v2_token_len = 0;
            }
        }
    }

    /* Get the name of the instance role */
    ret = get_metadata(implementation->client, AWS_IMDS_ROLE_PATH,
                       &instance_role, &instance_role_len,
                       implementation->imds_v2_token,
                       implementation->imds_v2_token_len);

    if (ret < 0) {
        return -1;
    }

    flb_debug("[aws_credentials] Requesting credentials for instance role %s",
              instance_role);

    /* Construct path where we will find the credentials */
    cred_path_size = sizeof(char) * (AWS_IMDS_ROLE_PATH_LEN +
                                     instance_role_len) + 1;
    cred_path = flb_malloc(cred_path_size);
    if (!cred_path) {
        flb_sds_destroy(instance_role);
        flb_errno();
        return -1;
    }

    ret = snprintf(cred_path, cred_path_size, "%s%s", AWS_IMDS_ROLE_PATH,
                   instance_role);
    if (ret < 0) {
        flb_sds_destroy(instance_role);
        flb_free(cred_path);
        flb_errno();
        return -1;
    }

    /* request creds */
    ret = ec2_credentials_request(implementation, cred_path);

    if (ret >= 0 && implementation->imds_v2_token_len == 0) {
        /* successfully got creds from v1; v1 is available */
        implementation->imds_version = 1;
        /*
         * TODO: re-enable when IMDSv2 support is added
         * flb_debug("[aws_credentials] IMDSv1 is available, and v2 appears "
         *      "unavailable. Will use v1 from now on");
         */
    }

    flb_sds_destroy(instance_role);
    flb_free(cred_path);
    return ret;

}

static int ec2_credentials_request(struct aws_credentials_provider_ec2
                                   *implementation, char *cred_path)
{
    int ret;
    flb_sds_t credentials_response;
    size_t credentials_response_len;
    struct aws_credentials *creds;
    time_t expiration;

    ret = get_metadata(implementation->client, cred_path,
                       &credentials_response, &credentials_response_len,
                       implementation->imds_v2_token,
                       implementation->imds_v2_token_len);

    if (ret < 0) {
        return -1;
    }

    creds = process_http_credentials_response(credentials_response,
                                              credentials_response_len,
                                              &expiration);

    if (creds == NULL) {
        flb_sds_destroy(credentials_response);
        return -1;
    }
    implementation->creds = creds;
    implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;

    flb_sds_destroy(credentials_response);
    return 0;
}
