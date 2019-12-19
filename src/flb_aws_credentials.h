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


/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"

/* Refresh token if it will expire in 10 min or less */
#define FLB_AWS_REFRESH_WINDOW         600

#define FLB_AWS_IMDS_V2_ROLE_PATH      "/latest/meta-data/iam/security-credentials/"
#define FLB_AWS_IMDS_V2_ROLE_PATH_LEN  43

/* HTTP Credentials Endpoints have a standard set of JSON Keys */
#define AWS_HTTP_RESPONSE_ACCESS_KEY = "AccessKeyId"
#define AWS_HTTP_RESPONSE_SECRET_KEY = "SecretAccessKey"
#define AWS_HTTP_RESPONSE_TOKEN      = "Token"

/*
 * A structure that wraps the sensitive data needed to sign an AWS request
 */
struct aws_credentials {
    flb_sds_t access_key_id;
    flb_sds_t secret_access_key;
    flb_sds_t session_token;
};

/*
 * Function to free memory used by an aws_credentials structure
 */
void aws_credentials_destroy(struct aws_credentials *creds);

/*
 * Get credentials using the provider.
 * Client is in charge of freeing the returned credentials struct.
 * Returns NULL if credentials could not be obtained.
 */
typedef aws_credentials*(aws_credentials_provider_get_credentials_fn)(struct aws_credentials_provider *provider);

/*
 * Force a refesh of credentials. This is needed for providers that cache
 * credentials. If the client receives a response from AWS indicating that
 * the credentials are expired, they can call this method.
 */
typedef int(aws_credentials_provider_refresh_fn)(struct aws_credentials_provider *provider);


/*
 * Clean up the underlying provider implementation
 * Clients should call this and then free the aws_credentials_provider structure.
 */
typedef void(aws_credentials_provider_destroy_fn)(struct aws_credentials_provider *provider);

/*
 * This structure is a virtual table that allows the client to get credentials.
 * And clean up all memory from the underlying implementation.
 */
struct aws_credentials_provider_vtable {
    aws_credentials_provider_get_credentials_fn *get_credentials;
    aws_credentials_provider_refresh_fn *refresh;
    aws_credentials_provider_destroy_fn *destroy;
};

/*
 * A generic structure to represent all providers.
 */
struct aws_credentials_provider {
    struct aws_credentials_provider_vtable *provider_vtable;
    void *implementation;
};

/*
 * A provider that wraps another provider and adds a cache.
 */
struct aws_credentials_provider *new_cached_provider(struct
                                                    aws_credentials_provider
                                                    *provider, unsigned long ttl);

/*
 * Standard Environment variables
 */
struct aws_credentials_provider *new_environment_provider();

/*
 * New EC2 IMDS provider
 */
struct aws_credentials_provider *new_imds_provider();

/*
 * New ECS provider
 */
struct aws_credentials_provider *new_ecs_provider();

/*
 * New http provider
 */
struct aws_credentials_provider *new_http_provider();

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
struct aws_credentials_provider *new_standard_chain_provider();


#endif
#endif /* FLB_HAVE_AWS */
