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

/*
 * A structure that wraps the sensitive data needed to sign an AWS request
 */
struct flb_aws_credentials {
    flb_sds_t access_key_id;
    flb_sds_t secret_access_key;
    flb_sds_t session_token;
};

/* defined below but declared here for the function declarations */
struct flb_aws_provider;

/*
 * Get credentials using the provider.
 * Client is in charge of freeing the returned credentials struct.
 * Returns NULL if credentials could not be obtained.
 */
typedef struct flb_aws_credentials*(flb_aws_provider_get_credentials_fn)
                                   (struct flb_aws_provider *provider);

/*
 * Force a refesh of cached credentials. If client code receives a response
 * from AWS indicating that the credentials are expired or invalid,
 * it can call this method and retry.
 * Returns 0 if the refresh was successful.
 */
typedef int(flb_aws_provider_refresh_fn)(struct flb_aws_provider *provider);


/*
 * Clean up the underlying provider implementation.
 * Called by flb_aws_provider_destroy.
 */
typedef void(flb_flb_aws_provider_destroy_fn)(struct flb_aws_provider *provider);

/*
 * This structure is a virtual table that allows the client to get credentials.
 * And clean up all memory from the underlying implementation.
 */
struct flb_aws_provider_vtable {
    flb_aws_provider_get_credentials_fn *get_credentials;
    flb_aws_provider_refresh_fn *refresh;
    flb_flb_aws_provider_destroy_fn *destroy;
};

/*
 * A generic structure to represent all providers.
 */
struct flb_aws_provider {
    struct flb_aws_provider_vtable *provider_vtable;
    void *implementation;

    /* Standard credentials chain is a list of providers */
    struct mk_list _head;
};

/*
 * Function to free memory used by an aws_credentials structure
 */
void flb_aws_credentials_destroy(struct flb_aws_credentials *creds);

/*
 * Function to free memory used by an flb_aws_provider structure
 */
void flb_aws_provider_destroy(struct flb_aws_provider *provider);

/*
 * A provider that uses OIDC tokens provided by kubernetes to obtain
 * AWS credentials.
 *
 * The AWS SDKs have defined a spec for an OIDC provider that obtains tokens
 * from environment variables or the shared config file.
 * This provider only contains the functionality needed for EKS- obtaining the
 * location of the OIDC token from an environment variable.
 */
struct flb_aws_provider *flb_eks_provider_create(struct flb_config *config,
                                                  struct flb_tls *tls,
                                                  char *region, char *proxy,
                                                  struct
                                                  flb_aws_client_generator
                                                  *generator);


/*
 * STS Assume Role Provider.
 */
struct flb_aws_provider *flb_sts_provider_create(struct flb_config *config,
                                                  struct flb_tls *tls,
                                                  struct flb_aws_provider
                                                  *base_provider,
                                                  char *external_id,
                                                  char *role_arn,
                                                  char *session_name,
                                                  char *region,
                                                  char *proxy,
                                                  struct
                                                  flb_aws_client_generator
                                                  *generator);

/*
 * Standard environment variables
 */
struct flb_aws_provider *flb_aws_env_provider_create();

/*
 * Helper functions
 */

time_t flb_aws_cred_expiration(const char* timestamp);

int flb_read_file(const char *path, char **out_buf, size_t *out_size);

struct flb_aws_credentials *flb_parse_sts_resp(char *response,
                                             time_t *expiration);
char *flb_sts_uri(char *action, char *role_arn, char *session_name,
                  char *external_id, char *identity_token);
char *flb_sts_session_name();


#endif
#endif /* FLB_HAVE_AWS */
