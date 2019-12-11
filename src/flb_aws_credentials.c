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
    unsigned long expiration;

    /* upstream connection to IMDS */
    struct flb_upstream *upstream;
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


int get_credentials_fn_environment(struct aws_credentials_provider *provider) {

}

/*
 * Force a refesh of credentials. This is needed for providers that cache
 * credentials. If the client receives a response from AWS indicating that
 * the credentials are expired, they can call this method.
 */
typedef int(aws_credentials_provider_refresh_fn)(struct aws_credentials_provider *provider);


/* Clean up the underlying provider implementation */
typedef void(aws_credentials_provider_destroy_fn)(struct aws_credentials_provider *provider);
