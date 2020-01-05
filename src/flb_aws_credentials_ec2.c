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

/* EC2 IMDS Provider */

aws_credentials *get_credentials_fn_ec2(struct aws_credentials_provider *provider) {
    aws_credentials *creds;
    int ret;
    struct aws_credentials_provider_ec2 *implementation = provider->implementation;

    flb_debug("[aws_credentials] Requesting credentials from the EC2 provider..");

    if (!implementation->creds || time(NULL) > implementation->cred_refresh) {
        ret = get_creds_ec2(implementation);
        if (ret < 0) {
            return NULL:
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

    creds->secret_access_key = flb_sds_create(implementation->creds->secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        aws_credentials_destroy(creds);
        return NULL;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->session_token);
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
    struct aws_credentials_provider_ec2 *implementation = provider->implementation;
    flb_debug("[aws_credentials] Refresh called on the EC2 IMDS provider");
    return get_creds_ec2(implementation);
}

void destroy_fn_ec2(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_ec2 *implementation = provider->implementation;

    if (implementation) {
        if (implementation->creds) {
            aws_credentials_destroy(implementation->creds);
        }

        if (implementation->upstream) {
            flb_upstream_destroy(implementation->upstream);
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

    provider->provider_vtable = &imds_provider_vtable;
    provider->implementation = implementation;

    upstream = flb_upstream_create(config, AWS_IMDS_V2_HOST, 80,
                                   FLB_IO_TCP, NULL);
    if (!upstream) {
        aws_provider_destroy(provider);
        flb_error("[aws_credentials] EC2 IMDS: connection initialization error");
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
    implementation->client->port = 80
    implementation->client->flags = 0;
    implementation->client->proxy = NULL;
    implementation->client->upstream = upstream;

    return provider;
}

/* Requests creds from IMDS and sets them on the provider */
static int get_creds_ec2(struct aws_credentials_provider_ec2 *implementation)
{
    int ret;
    flb_sds_t instance_role;
    size_t instance_role_len;
    char *cred_path;
    size_t cred_path_size;

    flb_debug("[aws_credentials] requesting credentials from EC2 IMDS");

    if (!implementation->imds_v2_token || (time(NULL) > implementation->token_refresh)) {
        flb_debug("[aws_credentials] requesting a new IMDSv2 token");
        ret = get_ec2_token(implementation->client,
                            &implementation->imds_v2_token,
                            &implementation->imds_v2_token_len);
        if (ret < 0) {
            return -1;
        }

        implementation->token_refresh = time(NULL)
                                        + AWS_IMDS_V2_TOKEN_TTL
                                        - FLB_AWS_REFRESH_WINDOW;
    }

    /* Get the name of the instance role */
    ret = get_metadata(implementation->client, AWS_IMDS_V2_ROLE_PATH,
                       &instance_role, &instance_role_len,
                       implementation->imds_v2_token,
                       implementation->imds_v2_token_len);

    if (ret < 0) {
        return -1;
    }

    flb_debug("[aws_credentials] Requesting credentials for instance role %s",
              instance_role);

    /* Construct path where we will find the credentials */
    cred_path_size = sizeof(char) * (AWS_IMDS_V2_ROLE_PATH_LEN + instance_role_len) + 1;
    cred_path = flb_malloc(cred_path_size);
    if (!cred_path) {
        flb_sds_destroy(instance_role);
        flb_errno();
        return -1;
    }

    ret = snprintf(cred_path, cred_path_size, "%s%s", AWS_IMDS_V2_ROLE_PATH, instance_role);
    if (ret < 0) {
        flb_sds_destroy(instance_role);
        flb_free(cred_path);
        flb_errno();
        return -1;
    }

    /* request creds */
    ret = ec2_credentials_request(implementation, cred_path);

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
    implementation->cred_refresh = expiration - FLB_AWS_REFRESH_WINDOW;

    flb_sds_destroy(credentials_response);
    return 0;
}
