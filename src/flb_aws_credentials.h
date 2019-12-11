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

#ifdef FLB_HAVE_AWS_CREDS

#ifndef FLB_AWS_CREDENTIALS_H
#define FLB_AWS_CREDENTIALS_H

/*
 * A structure that wraps the sensitive data needed to sign an AWS request
 */
struct aws_credentials {
    flb_sds_t *access_key_id;
    flb_sds_t *secret_access_key;
    flb_sds_t *session_token;
};

/* Get credentials using the provider */
typedef void(aws_credentials_provider_get_credentials_fn)(struct aws_credentials_provider *provider);

/*
 * Force a refesh of credentials. This is needed for providers that cache
 * credentials. If the client receives a response from AWS indicating that
 * the credentials are expired, they can call this method.
 */
typedef void(aws_credentials_provider_refresh_fn)(struct aws_credentials_provider *provider);


/* Clean up the underlying provider implementation */
typedef void(aws_credentials_provider_destroy_fn)(struct aws_credentials_provider *provider);

/*
 * This structure is a virtual table that allows the client to get credentials.
 * And clean up all memory from the underlying implementation.
 */
struct aws_credentials_provider_vtable {
    aws_credentials_provider_get_credentials_fn *get_credentials;
    aws_credentials_provider_refresh_fn *refresh;
    aws_credentials_provider_destroy_fn *destroy;
    void *implementation;
};

/*
 * A generic structure to represent all providers.
 */
struct aws_credentials_provider {
    struct aws_credentials_provider_vtable *provider_vtable;
    void *implementation;
};

/*
 * A provider that wraps other providers and adds a cache.
 */
struct aws_credentials_provider_cached {
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
struct aws_credentials_provider_http {
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
struct aws_credentials_provider_imds {
    struct aws_credentials *credentials;
    unsigned long expiration;

    /* upstream connection to IMDS */
    struct flb_upstream *upstream;
};



#endif
#endif /* FLB_HAVE_AWS_CREDS */
