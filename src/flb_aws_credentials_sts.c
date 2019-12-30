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
#include <string.h>

#define STS_ASSUME_ROLE_URI_FORMAT    "/?Version=2011-06-15&Action=AssumeRole\
&RoleSessionName=%s&RoleArn=%s"
#define STS_ASSUME_ROLE_URI_BASE_LEN  64

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


/*
 * A provider that uses credentials from the base provider to call STS
 * and assume an IAM Role.
 */
static struct aws_credentials_provider_sts {
    struct aws_credentials_provider *base_provider;

    struct aws_credentials creds;
    time_t next_refresh;

    struct aws_http_client *sts_client;

    /* Fluent Bit uses regional STS endpoints; this is a best practice. */
    char *endpoint;

    char *uri;
};

struct aws_credentials_provider *new_sts_assume_role_provider(struct flb_config
                                                              *config,
                                                              struct flb_tls *tls,
                                                              struct
                                                              aws_credentials_provider
                                                              base_provider,
                                                              char *external_id,
                                                              char *role_arn,
                                                              char *session_name,
                                                              char *region,
                                                              char *proxy,
                                                              aws_http_client_generator
                                                              *generator)
{
    struct aws_credentials_provider_sts *implementation;
    struct aws_credentials_provider *provider;
    struct flb_upstream *upstream;

    provider = flb_calloc(1, sizeof(struct aws_credentials_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct aws_credentials_provider_sts));

    if (!implementation) {
        goto error;
    }

    provider->provider_vtable = &sts_provider_vtable;
    provider->implementation = implementation;

    implementation->uri = sts_uri(role_arn, session_name, external_id);
    if (!implementation->uri) {
        goto error;
    }

    implementation->endpoint = endpoint_for("sts", region);
    if (!implementation->endpoint) {
        goto error;
    }

    implementation->base_provider = base_provider;
    implementation->sts_client = generator->new();
    if (!implementation->sts_client) {
        goto error;
    }
    implementation->sts_client->name = "sts_client";
    implementation->sts_client->has_auth = FLB_TRUE;
    implementation->sts_client->provider = base_provider;
    implementation->sts_client->region = region;
    implementation->sts_client->service = "sts";
    implementation->sts_client->port = 80
    implementation->sts_client->flags = 0;
    implementation->sts_client->proxy = proxy;

    upstream = flb_upstream_create(config, implementation->endpoint, 80,
                                   FLB_IO_TLS, tls);

    implementation->sts_client->upstream = upstream;
    implementation->endpoint->host = implementation->endpoint;

error:
    flb_errno();
    aws_provider_destroy(provider);
    return NULL;
}


aws_credentials *get_credentials_fn_sts(struct aws_credentials_provider *provider) {
    aws_credentials *creds;
    int ret;
    struct aws_credentials_provider_sts *implementation = provider->implementation;

    flb_debug("[aws_credentials] Requesting credentials from the STS provider..");

    if (!implementation->credentials || time(NULL) > implementation->next_refresh) {
        ret = sts_assume_role_request(implementation);
        if (ret < 0) {
            return NULL:
        }
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->secret_access_key);
    if (!creds->secret_access_key) {
        goto error;
    }

    if (implementation->credentials->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->session_token);
        if (!creds->session_token) {
            goto error;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_errno();
    aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_sts(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_sts *implementation = provider->implementation;
    flb_debug("[aws_credentials] Refresh called on the STS provider");
    return sts_assume_role_request(implementation);;
}

void destroy_fn_sts(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_sts *implementation = provider->implementation;
    if (implementation) {
        if (implementation->credentials) {
            aws_credentials_destroy(implementation->credentials);
        }

        if (implementation->sts_client) {
            aws_client_destroy(implementation->sts_client);
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

static struct aws_credentials_provider_vtable sts_provider_vtable = {
    .get_credentials = get_credentials_fn_sts,
    .refresh = refresh_fn_sts,
    .destroy = destroy_fn_sts,
};

static int sts_assume_role_request(struct aws_credentials_provider_sts
                                   *implementation)
{
    int ret;
    time_t expiration;
    struct aws_http_client sts_client = implementation->sts_client;

    ret = sts_client->client_vtable->request(sts_client, FLB_HTTP_GET,
                                             implementation->uri, NULL, 0,
                                             NULL, 0);

    if (ret == 0 && sts_client->c->resp.status == 200) {
        implementation->creds = process_sts_response(sts_client->c->resp.payload,
                                                     &expiration);
        if (!implementation->creds) {
            flb_error("[aws_credentials] Failed to parse response from STS");
            return -1;
        }
        implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
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
static struct aws_credentials *process_sts_response(char *response,
                                                    time_t *expiration)
{
    struct aws_credentials *creds;
    char *cred_node;
    flb_sds_t tmp = NULL;

    cred_node = strstr(response, CREDENTIALS_NODE);
    if (!cred_node) {
        flb_error("[aws_credentials] Could not find '%s' node in sts response",
                  CREDENTIALS_NODE);
        return NULL;
    }
    cred_node += CREDENTIALS_NODE_LEN;

    creds = flb_malloc(sizeof(struct aws_credentials));
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
    *expiration = parse_expiration(tmp);
    if (*expiration == 0) {
        flb_error("[aws_credentials] Could not parse expiration in sts response");
        goto error;
    }

    flb_sds_destroy(tmp);
    return creds;

error:
    aws_credentials_destroy(creds);
    if (tmp) {
        flb_sds_destroy(tmp);
    }
    return NULL;
}

/*
 * Constructs the STS request uri.
 * external_id can be NULL.
 */
static char *sts_uri(char *role_arn, char *session_name, char *external_id)
{
    char *uri;
    size_t len = STS_ASSUME_ROLE_URI_BASE_LEN;

    if (external_id) {
        len += 12; /* will add "&ExternalId=" */
        len += strlen(external_id);
    }

    len += strlen(session_name);
    len += strlen(role_arn);

    uri = flb_malloc(size(char) * (len + 1));
    if (!uri) {
        flb_errno();
        return NULL;
    }

    snprintf(uri, len, STS_ASSUME_ROLE_URI_FORMAT, session_name, role_arn);

    if (implementation->external_id) {
        strncat(uri, "&ExternalId=", 12);
        strncat(uri, external_id, strlen(external_id));
    }

    return uri;
}

static flb_sds_t get_node(char *cred_node, char* node_name, int node_len)
{
    char *node;
    char *end;
    flb_sds_t val;

    node = strstr(cred_node, node_name);
    if (!node) {
        flb_error("[aws_credentials] Could not find '%s' node in sts response",
                  node_name);
        return NULL;
    }
    node += node_len;
    end = strchr(node, '<');
    if (!end) {
        flb_error("[aws_credentials] Could not find end of '%s' node in sts response",
                  node_name);
        return NULL;
    }
    *end = '\0';

    val = flb_sds_create(node);
    if (!val) {
        flb_errno();
        return NULL;
    }

    return val;
}
