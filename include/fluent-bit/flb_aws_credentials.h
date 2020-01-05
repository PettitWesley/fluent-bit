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

#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <monkey/mk_core.h>

/* Refresh if creds they will expire in 5 min or less */
#define FLB_AWS_REFRESH_WINDOW         300

/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"

/* HTTP Credentials Endpoints have a standard set of JSON Keys */
#define AWS_HTTP_RESPONSE_ACCESS_KEY   "AccessKeyId"
#define AWS_HTTP_RESPONSE_SECRET_KEY   "SecretAccessKey"
#define AWS_HTTP_RESPONSE_TOKEN        "Token"
#define AWS_HTTP_RESPONSE_EXPIRATION   "Expiration"

#define ECS_CREDENTIALS_HOST           "169.254.170.2"
#define ECS_CREDENTIALS_HOST_LEN       13
#define ECS_CREDENTIALS_PATH_ENV_VAR   "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"

/*
 * A structure that wraps the sensitive data needed to sign an AWS request
 */
struct aws_credentials {
    flb_sds_t access_key_id;
    flb_sds_t secret_access_key;
    flb_sds_t session_token;
};

/* defined below but declared here for the function declarations */
struct aws_credentials_provider;

/*
 * Get credentials using the provider.
 * Client is in charge of freeing the returned credentials struct.
 * Returns NULL if credentials could not be obtained.
 */
typedef struct aws_credentials*(aws_credentials_provider_get_credentials_fn)
                               (struct aws_credentials_provider *provider);

/*
 * Force a refesh of cached credentials. If client code receives a response
 * from AWS indicating that the credentials are expired or invalid,
 * it can call this method and retry.
 * Returns 0 if the refresh was successful.
 */
typedef int(aws_credentials_provider_refresh_fn)(struct aws_credentials_provider
                                                 *provider);


/*
 * Clean up the underlying provider implementation.
 * Called by aws_provider_destroy.
 */
typedef void(aws_credentials_provider_destroy_fn)(struct
                                                  aws_credentials_provider
                                                  *provider);

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

    /* Standard credentials chain is a list of providers */
    struct mk_list _head;
};

/*
 * Function to free memory used by an aws_credentials structure
 */
void aws_credentials_destroy(struct aws_credentials *creds);

/*
 * Function to free memory used by an aws_credentials_provider structure
 */
void aws_provider_destroy(struct aws_credentials_provider *provider);

/*
 * A provider that uses OIDC tokens provided by kubernetes to obtain
 * AWS credentials.
 *
 * The AWS SDKs have defined a spec for an OIDC provider that obtains tokens
 * from environment variables or the shared config file.
 * This provider only contains the functionality needed for EKS- obtaining the
 * location of the OIDC token from an environment variable.
 */
struct aws_credentials_provider *new_eks_provider(struct flb_config *config,
                                                  struct flb_tls *tls,
                                                  char *region, char *proxy,
                                                  struct
                                                  aws_http_client_generator
                                                  *generator);


/*
 * STS Assume Role Provider.
 */
struct aws_credentials_provider *new_sts_provider(struct flb_config *config,
                                                  struct flb_tls *tls,
                                                  struct
                                                  aws_credentials_provider
                                                  *base_provider,
                                                  char *external_id,
                                                  char *role_arn,
                                                  char *session_name,
                                                  char *region,
                                                  char *proxy,
                                                  struct
                                                  aws_http_client_generator
                                                  *generator);

/*
 * Standard environment variables
 */
struct aws_credentials_provider *new_environment_provider();


/*
 * New http provider - retrieve credentials from a local http server.
 * Equivalent to:
 * https://github.com/aws/aws-sdk-go/tree/master/aws/credentials/endpointcreds
 *
 * Calling aws_provider_destroy on this provider frees the memory
 * used by host and path.
 */
struct aws_credentials_provider *new_http_provider(struct flb_config *config,
                                                   flb_sds_t host,
                                                   flb_sds_t path,
                                                   struct
                                                   aws_http_client_generator
                                                   *generator);

/*
 * ECS Provider
 * The ECS Provider is just a wrapper around the HTTP Provider
 * with the ECS credentials endpoint.
 */

struct aws_credentials_provider *new_ecs_provider(struct flb_config *config,
                                                  struct
                                                  aws_http_client_generator
                                                  *generator);

/*
 * New EC2 IMDS provider
 */
struct aws_credentials_provider *new_ec2_provider(struct flb_config *config,
                                                  struct
                                                  aws_http_client_generator
                                                  *generator);

/*
 * Helper functions
 */

time_t credential_expiration(const char* timestamp);

int file_to_buf(const char *path, char **out_buf, size_t *out_size);

struct aws_credentials *process_sts_response(char *response,
                                             time_t *expiration);
char *sts_uri(char *action, char *role_arn, char *session_name,
              char *external_id, char *identity_token);
char *random_session_name();

struct aws_credentials *process_http_credentials_response(char *response,
                                                          size_t response_len,
                                                          time_t *expiration)


#endif
#endif /* FLB_HAVE_AWS */
