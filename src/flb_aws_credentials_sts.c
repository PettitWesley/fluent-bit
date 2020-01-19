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

#include <mbedtls/ctr_drbg.h>
#include "mbedtls/entropy.h"
#include <jsmn/jsmn.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define STS_ASSUME_ROLE_URI_FORMAT    "/?Version=2011-06-15&Action=%s\
&RoleSessionName=%s&RoleArn=%s"
#define STS_ASSUME_ROLE_URI_BASE_LEN  54

#define CREDENTIALS_NODE              "<Credentials>"
#define CREDENTIALS_NODE_LEN          13
#define ACCESS_KEY_NODE               "<AccessKeyId>"
#define ACCESS_KEY_NODE_LEN           13
#define SECRET_KEY_NODE               "<SecretAccessKey>"
#define SECRET_KEY_NODE_LEN           17
#define SESSION_TOKEN_NODE            "<SessionToken>"
#define SESSION_TOKEN_NODE_LEN        14
#define EXPIRATION_NODE               "<Expiration>"
#define EXPIRATION_NODE_LEN           12

#define TOKEN_FILE_ENV_VAR            "AWS_WEB_IDENTITY_TOKEN_FILE"
#define ROLE_ARN_ENV_VAR              "AWS_ROLE_ARN"
#define SESSION_NAME_ENV_VAR          "AWS_ROLE_SESSION_NAME"

#define SESSION_NAME_RANDOM_BYTE_LEN  32

struct flb_aws_provider_eks;
void bytes_to_string(unsigned char *data, char *buf, size_t len);
static int assume_with_web_identity(struct flb_aws_provider_eks
                                    *implementation);
static int sts_assume_role_request(struct flb_aws_client *sts_client,
                                   struct flb_aws_credentials **creds,
                                   char *uri,
                                   time_t *next_refresh);
static flb_sds_t get_node(char *cred_node, char* node_name, int node_len);


/*
 * A provider that uses credentials from the base provider to call STS
 * and assume an IAM Role.
 */
struct flb_aws_provider_sts {
    struct flb_aws_provider *base_provider;

    struct flb_aws_credentials *creds;
    time_t next_refresh;

    struct flb_aws_client *sts_client;

    /* Fluent Bit uses regional STS endpoints; this is a best practice. */
    char *endpoint;

    char *uri;
};

struct flb_aws_credentials *get_credentials_fn_sts(struct flb_aws_provider
                                                   *provider)
{
    struct flb_aws_credentials *creds;
    int ret;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_sts *implementation = provider->
                                                          implementation;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "STS provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
        flb_debug("[aws_credentials] STS Provider: Refreshing credential "
                  "cache.");
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        ret = sts_assume_role_request(implementation->sts_client,
                                      &implementation->creds,
                                      implementation->uri,
                                      &implementation->next_refresh);
        if (ret < 0) {
            return NULL;
        }
    }

    creds = flb_malloc(sizeof(struct flb_aws_credentials));
    if (!creds) {
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            goto error;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_errno();
    flb_aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_sts(struct flb_aws_provider *provider) {
    struct flb_aws_provider_sts *implementation = provider->
                                                          implementation;
    flb_debug("[aws_credentials] Refresh called on the STS provider");
    int ret = sts_assume_role_request(implementation->sts_client,
                                   &implementation->creds, implementation->uri,
                                   &implementation->next_refresh);
    return ret;
}

void destroy_fn_sts(struct flb_aws_provider *provider) {
    struct flb_aws_provider_sts *implementation = provider->
                                                          implementation;
    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }

        if (implementation->sts_client) {
            flb_aws_client_destroy(implementation->sts_client);
        }

        if (implementation->uri) {
            flb_free(implementation->uri);
        }

        if (implementation->endpoint) {
            flb_free(implementation->endpoint);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct flb_aws_provider_vtable sts_provider_vtable = {
    .get_credentials = get_credentials_fn_sts,
    .refresh = refresh_fn_sts,
    .destroy = destroy_fn_sts,
};

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
                                                 *generator)
{
    struct flb_aws_provider_sts *implementation = NULL;
    struct flb_aws_provider *provider = NULL;
    struct flb_upstream *upstream = NULL;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_sts));

    if (!implementation) {
        goto error;
    }

    provider->provider_vtable = &sts_provider_vtable;
    provider->implementation = implementation;

    implementation->uri = flb_sts_uri("AssumeRole", role_arn, session_name,
                                  external_id, NULL);
    if (!implementation->uri) {
        goto error;
    }

    implementation->endpoint = flb_aws_endpoint("sts", region);
    if (!implementation->endpoint) {
        goto error;
    }

    implementation->base_provider = base_provider;
    implementation->sts_client = generator->create();
    if (!implementation->sts_client) {
        goto error;
    }
    implementation->sts_client->name = "sts_client_assume_role_provider";
    implementation->sts_client->has_auth = FLB_TRUE;
    implementation->sts_client->provider = base_provider;
    implementation->sts_client->region = region;
    implementation->sts_client->service = "sts";
    implementation->sts_client->port = 443;
    implementation->sts_client->flags = 0;
    implementation->sts_client->proxy = proxy;

    upstream = flb_upstream_create(config, implementation->endpoint, 443,
                                   FLB_IO_TLS, tls);
    if (!upstream) {
        flb_error("[aws_credentials] Connection initialization error");
        goto error;
    }

    implementation->sts_client->upstream = upstream;
    implementation->sts_client->host = implementation->endpoint;

    return provider;

error:
    flb_errno();
    flb_aws_provider_destroy(provider);
    return NULL;
}

/*
 * A provider that uses OIDC tokens provided by kubernetes to obtain
 * AWS credentials.
 *
 * The AWS SDKs have defined a spec for an OIDC provider that obtains tokens
 * from environment variables or the shared config file.
 * This provider only contains the functionality needed for EKS- obtaining the
 * location of the OIDC token from an environment variable.
 */
struct flb_aws_provider_eks {
    struct flb_aws_credentials *creds;
    /*
     * Time to auto-refresh creds before they expire. A negative value disables
     * auto-refresh. Client code can always force a refresh.
     */
    time_t next_refresh;

    struct flb_aws_client *sts_client;

    /* Fluent Bit uses regional STS endpoints; this is a best practice. */
    char *endpoint;

    char *session_name;
    /* session name can come from env or be generated by the provider */
    int free_session_name;
    char *role_arn;

    char *token_file;
};


struct flb_aws_credentials *get_credentials_fn_eks(struct flb_aws_provider
                                                   *provider)
{
    struct flb_aws_credentials *creds = NULL;
    int ret;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_eks *implementation = provider->implementation;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "EKS provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
        flb_debug("[aws_credentials] EKS Provider: Refreshing credential "
                  "cache.");
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        ret = assume_with_web_identity(implementation);
        if (ret < 0) {
            return NULL;
        }
    }

    creds = flb_malloc(sizeof(struct flb_aws_credentials));
    if (!creds) {
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            goto error;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_errno();
    flb_aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_eks(struct flb_aws_provider *provider) {
    struct flb_aws_provider_eks *implementation = provider->
                                                          implementation;
    flb_debug("[aws_credentials] Refresh called on the EKS provider");
    return assume_with_web_identity(implementation);
}

void destroy_fn_eks(struct flb_aws_provider *provider) {
    struct flb_aws_provider_eks *implementation = provider->
                                                          implementation;
    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }

        if (implementation->sts_client) {
            flb_aws_client_destroy(implementation->sts_client);
        }

        if (implementation->endpoint) {
            flb_free(implementation->endpoint);
        }
        if (implementation->free_session_name == FLB_TRUE) {
            flb_free(implementation->session_name);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct flb_aws_provider_vtable eks_provider_vtable = {
    .get_credentials = get_credentials_fn_eks,
    .refresh = refresh_fn_eks,
    .destroy = destroy_fn_eks,
};

struct flb_aws_provider *flb_eks_provider_create(struct flb_config *config,
                                                 struct flb_tls *tls,
                                                 char *region, char *proxy,
                                                 struct
                                                 flb_aws_client_generator
                                                 *generator)
{
    struct flb_aws_provider_eks *implementation = NULL;
    struct flb_aws_provider *provider = NULL;
    struct flb_upstream *upstream = NULL;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_eks));

    if (!implementation) {
        goto error;
    }

    provider->provider_vtable = &eks_provider_vtable;
    provider->implementation = implementation;

    /* session name either comes from the env var or is a random uuid */
    implementation->session_name = getenv(SESSION_NAME_ENV_VAR);
    implementation->free_session_name = FLB_FALSE;
    if (!implementation->session_name ||
        strlen(implementation->session_name) == 0) {
        implementation->session_name = flb_sts_session_name();
        if (!implementation->session_name) {
            goto error;
        }
        implementation->free_session_name = FLB_TRUE;
    }

    implementation->role_arn = getenv(ROLE_ARN_ENV_VAR);
    if (!implementation->role_arn || strlen(implementation->role_arn) == 0) {
        flb_debug("[aws_credentials] Not initializing EKS provider because"
                  " %s was not set", ROLE_ARN_ENV_VAR);
        goto error;
    }

    implementation->token_file = getenv(TOKEN_FILE_ENV_VAR);
    if (!implementation->token_file || strlen(implementation->token_file) == 0)
    {
        flb_debug("[aws_credentials] Not initializing EKS provider because"
                  " %s was not set", TOKEN_FILE_ENV_VAR);
        goto error;
    }

    implementation->endpoint = flb_aws_endpoint("sts", region);
    if (!implementation->endpoint) {
        goto error;
    }

    implementation->sts_client = generator->create();
    if (!implementation->sts_client) {
        goto error;
    }
    implementation->sts_client->name = "sts_client_eks_provider";
    /* AssumeRoleWithWebIdentity does not require sigv4 */
    implementation->sts_client->has_auth = FLB_FALSE;
    implementation->sts_client->provider = NULL;
    implementation->sts_client->region = region;
    implementation->sts_client->service = "sts";
    implementation->sts_client->port = 443;
    implementation->sts_client->flags = 0;
    implementation->sts_client->proxy = proxy;

    upstream = flb_upstream_create(config, implementation->endpoint, 443,
                                   FLB_IO_TLS, tls);

    implementation->sts_client->upstream = upstream;
    implementation->sts_client->host = implementation->endpoint;

    return provider;

error:
    flb_errno();
    flb_aws_provider_destroy(provider);
    return NULL;
}

/* Generates string which can serve as a unique session name */
char *flb_sts_session_name() {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    char *personalization = NULL;
    time_t now;
    unsigned char *random_data = NULL;
    char *session_name = NULL;
    int ret;

    personalization = flb_malloc(sizeof(char) * 27);
    if (!personalization) {
        goto error;
    }

    now = time(NULL);
    ctime_r(&now, personalization);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) personalization,
                                strlen(personalization));
    if (ret != 0) {
        goto error;
    }

    random_data = flb_malloc(sizeof(unsigned char) *
                             SESSION_NAME_RANDOM_BYTE_LEN);
    if (!random_data) {
        goto error;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, random_data,
                                  SESSION_NAME_RANDOM_BYTE_LEN);
    if (ret != 0) {
        goto error;
    }

    session_name = flb_malloc(sizeof(char) *
                              (SESSION_NAME_RANDOM_BYTE_LEN + 1));
    if (!session_name) {
        goto error;
    }

    bytes_to_string(random_data, session_name, SESSION_NAME_RANDOM_BYTE_LEN);
    session_name[SESSION_NAME_RANDOM_BYTE_LEN] = '\0';

    flb_free(random_data);
    flb_free(personalization);

    return session_name;

error:
    flb_errno();
    if (personalization) {
        flb_free(personalization);
    }
    if (random_data) {
        flb_free(random_data);
    }
    if (session_name) {
        flb_free(session_name);
    }
    return NULL;
}

/* converts random bytes to a string we can safely put in a URL */
void bytes_to_string(unsigned char *data, char *buf, size_t len) {
    int index;
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (len-- > 0) {
        index = (int) data[len];
        index = index % (sizeof(charset) - 1);
        buf[len] = charset[index];
    }
}

static int assume_with_web_identity(struct flb_aws_provider_eks
                                    *implementation)
{
    int ret;
    char *web_token = NULL;
    size_t web_token_size;
    char *uri = NULL;

    ret = flb_read_file(implementation->token_file, &web_token,
                        &web_token_size);
    if (ret < 0) {
        flb_error("[aws_credentials] Could not read web identify token file");
        return -1;
    }

    uri = flb_sts_uri("AssumeRoleWithWebIdentity", implementation->role_arn,
                  implementation->session_name, NULL, web_token);
    if (!uri) {
        flb_free(web_token);
        return -1;
    }

    ret = sts_assume_role_request(implementation->sts_client,
                                  &implementation->creds, uri,
                                  &implementation->next_refresh);
    flb_free(web_token);
    flb_free(uri);
    return ret;
}

static int sts_assume_role_request(struct flb_aws_client *sts_client,
                                   struct flb_aws_credentials **creds,
                                   char *uri,
                                   time_t *next_refresh)
{
    int ret;
    time_t expiration;
    struct flb_aws_credentials *credentials = NULL;
    /* unset and free existing credentials first */
    flb_aws_credentials_destroy(*creds);
    *creds = NULL;

    ret = sts_client->client_vtable->request(sts_client, FLB_HTTP_GET,
                                             uri, NULL, 0, NULL, 0);

    if (ret == 0 && sts_client->c->resp.status == 200) {
        credentials = flb_parse_sts_resp(sts_client->c->resp.payload,
                                                     &expiration);
        if (!credentials) {
            flb_error("[aws_credentials] Failed to parse response from STS");
            return -1;
        }

        *next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
        *creds = credentials;
        return 0;
    }

    if (sts_client->error_type) {
        flb_error("[aws_credentials] STS API responded with %s",
                  sts_client->error_type);
    }

    if (sts_client->c && sts_client->c->resp.payload_size > 0) {
        flb_debug("[aws_credentials] STS raw response: \n%s",
                  sts_client->c->resp.payload);
    }

    flb_error("[aws_credentials] STS assume role request failed");
    return -1;

}

/*
 * The STS APIs return an XML document with credentials.
 * The part of the document we care about looks like this:
 * <Credentials>
 *    <AccessKeyId>akid</AccessKeyId>
 *    <SecretAccessKey>skid</SecretAccessKey>
 *    <SessionToken>token</SessionToken>
 *    <Expiration>2019-11-09T13:34:41Z</Expiration>
 * </Credentials>
 */
struct flb_aws_credentials *flb_parse_sts_resp(char *response,
                                                    time_t *expiration)
{
    struct flb_aws_credentials *creds = NULL;
    char *cred_node;
    flb_sds_t tmp = NULL;

    cred_node = strstr(response, CREDENTIALS_NODE);
    if (!cred_node) {
        flb_error("[aws_credentials] Could not find '%s' node in sts response",
                  CREDENTIALS_NODE);
        return NULL;
    }
    cred_node += CREDENTIALS_NODE_LEN;

    creds = flb_malloc(sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        return NULL;
    }

    creds->access_key_id = get_node(cred_node, ACCESS_KEY_NODE,
                                    ACCESS_KEY_NODE_LEN);
    if (!creds->access_key_id) {
        goto error;
    }

    creds->secret_access_key = get_node(cred_node, SECRET_KEY_NODE,
                                        SECRET_KEY_NODE_LEN);
    if (!creds->secret_access_key) {
        goto error;
    }

    creds->session_token = get_node(cred_node, SESSION_TOKEN_NODE,
                                    SESSION_TOKEN_NODE_LEN);
    if (!creds->session_token) {
        goto error;
    }

    tmp = get_node(cred_node, EXPIRATION_NODE, EXPIRATION_NODE_LEN);
    if (!tmp) {
        goto error;
    }
    *expiration = flb_aws_cred_expiration(tmp);

    flb_sds_destroy(tmp);
    return creds;

error:
    flb_aws_credentials_destroy(creds);
    if (tmp) {
        flb_sds_destroy(tmp);
    }
    return NULL;
}

/*
 * Constructs the STS request uri.
 * external_id can be NULL.
 */
char *flb_sts_uri(char *action, char *role_arn, char *session_name,
              char *external_id, char *identity_token)
{
    char *uri = NULL;
    size_t len = STS_ASSUME_ROLE_URI_BASE_LEN;

    if (external_id) {
        len += 12; /* will add "&ExternalId=" */
        len += strlen(external_id);
    }

    if (identity_token) {
        len += 18; /* will add "&WebIdentityToken=" */
        len += strlen(identity_token);
    }


    len += strlen(session_name);
    len += strlen(role_arn);
    len += strlen(action);
    len++; /* null char */
    uri = flb_malloc(sizeof(char) * (len));
    if (!uri) {
        flb_errno();
        return NULL;
    }

    snprintf(uri, len, STS_ASSUME_ROLE_URI_FORMAT, action, session_name,
             role_arn);

    if (external_id) {
        strncat(uri, "&ExternalId=", 12);
        strncat(uri, external_id, strlen(external_id));
    }

    if (identity_token) {
        strncat(uri, "&WebIdentityToken=", 18);
        strncat(uri, identity_token, strlen(identity_token));
    }

    return uri;
}

static flb_sds_t get_node(char *cred_node, char* node_name, int node_len)
{
    char *node = NULL;
    char *end = NULL;
    flb_sds_t val = NULL;
    int len;

    node = strstr(cred_node, node_name);
    if (!node) {
        flb_error("[aws_credentials] Could not find '%s' node in sts response",
                  node_name);
        return NULL;
    }
    node += node_len;
    end = strchr(node, '<');
    if (!end) {
        flb_error("[aws_credentials] Could not find end of '%s' node in "
                  "sts response", node_name);
        return NULL;
    }
    len = end - node;
    val = flb_sds_create_len(node, len);
    if (!val) {
        flb_errno();
        return NULL;
    }

    return val;
}
