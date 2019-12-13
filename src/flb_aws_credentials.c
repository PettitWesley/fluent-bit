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

#include <stdlib.h>

/*
 * A provider that wraps other providers and adds a cache.
 */
static struct aws_credentials_provider_cached {
    struct aws_credentials *credentials;
    unsigned long next_refresh;
    unsigned long ttl;

    /* Underlying provider */
    struct aws_credentials_provider *provider;
};

/*
 * A provider that obtains credentials from an http endpoint.
 * On ECS the ECS Agent vends credentials via a link local IP address.
 * Some customers build local HTTP services that provide the same functionality.
 */
static struct aws_credentials_provider_http {
    struct aws_credentials *credentials;
    unsigned long expiration;

    /* upstream connection to host */
    struct flb_upstream *upstream;

    /* Host and Path to request credentials */
    char *host;
    char *path;
 };

/*
 * A provider that obtains credentials from EC2 IMDS.
 */
static struct aws_credentials_provider_imds {
    struct aws_credentials *credentials;
    unsigned long refresh;

    /* upstream connection to IMDS */
    struct flb_upstream *upstream;

    /* IMDSv2 Token */
    flb_sds_t imds_v2_token;
    size_t imds_v2_token_len;
    unsigned long token_expiration;
 };

/*
 * The standard credential provider chain:
 * 1. Environment variables
 * 2. Shared credentials file (AWS Profile)
 * 3. EC2 IMDS
 * 4. ECS HTTP credentials endpoint
 *
 * This provider will evaluate each provider in order, returning the result
 * from the first provider that returns valid credentials.
 *
 * Note: Client code should use this provider by default.
 */
struct aws_credentials_provider_default_chain {
    struct aws_credentials_provider *env_provider;
    struct aws_credentials_provider *profile_provider;
    struct aws_credentials_provider *ec2_provider;
    struct aws_credentials_provider *ecs_provider;
};

/* Environment Provider */
aws_credentials *get_credentials_fn_environment(struct aws_credentials_provider *provider) {
    char *access_key;
    char *secret_key;
    char *session_token;
    aws_credentials *creds;

    access_key = getenv(AWS_ACCESS_KEY_ID);
    if (!access_key) {
        return NULL
    }

    secret_key = getenv(AWS_SECRET_ACCESS_KEY);
    if (!secret_key) {
        flb_free(access_key);
        return NULL
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        flb_free(access_key);
        flb_free(secret_key);
        return NULL
    }

    creds->access_key_id = flb_sds_create(access_key);
    creds->secret_access_key = flb_sds_create(secret_key);

    session_token = getenv(AWS_SESSION_TOKEN);
    if (session_token) {
        creds->session_token = session_token;
    }

    return creds;

}

/* Refresh is a no-op for the env provider */
int refresh_fn_environment(struct aws_credentials_provider *provider) {
    return 0;
}


/* Destroy is a no-op for the env provider */
void destroy_fn_environment(struct aws_credentials_provider *provider) {
    return;
}

static struct aws_credentials_provider_vtable environment_provider_vtable = {
    .get_credentials = get_credentials_fn_environment,
    .refresh = refresh_fn_environment,
    .destroy = destroy_fn_environment,
};

struct aws_credentials_provider *new_environment_provider() {
    struct aws_credentials_provider provider = flb_malloc(
                                                          sizeof(
                                                          struct aws_credentials_provider));

    if (!provider) {
        return NULL;
    }

    provider->provider_vtable = &environment_provider_vtable;
    provider->implementation = NULL;

    return provider;
}

/* EC2 IMDS Provider */

aws_credentials *get_credentials_fn_imds(struct aws_credentials_provider *provider) {
    aws_credentials *creds;
    struct aws_credentials_provider_imds *implementation = provider->implementation;

    /* credentials have not been requested yet, or are about to expire */
    if (!implementation->credentials || ((unsigned long)time(NULL) > implementation->refresh)) {
        /* todo: make a call to imds to get creds */
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        return NULL
    }

    creds->access_key_id = flb_sds_create(implementation->credentials->access_key_id);
    creds->secret_access_key = flb_sds_create(implementation->credentials->secret_access_key);
    if (implementation->credentials->session_token) {
        creds->session_token = flb_sds_create(implementation->credentials->session_token);
    }

    return creds;
}


static int imds_request_creds(struct aws_credentials_provider_imds *implementation)
{
    //implementation->token_expiration = (unsigned long) time(NULL) + FLB_AWS_IMDS_V2_TOKEN_TTL

}


struct aws_credentials_provider *new_imds_provider() {
    struct aws_credentials_provider provider = flb_malloc(
                                                          sizeof(
                                                          struct aws_credentials_provider));

    if (!provider) {
        return NULL;
    }
}
