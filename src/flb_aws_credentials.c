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

#define TEN_MINUTES    600
#define TWELVE_HOURS   43200

/* Declarations */
struct aws_credentials_provider_http *implementation;
static int http_credentials_request(struct aws_credentials_provider_http
                                    *implementation);

/* Environment Provider */
struct aws_credentials *get_credentials_fn_environment(struct
                                                       aws_credentials_provider
                                                       *provider)
{
    char *access_key;
    char *secret_key;
    char *session_token;
    struct aws_credentials *creds;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "env provider..");

    access_key = getenv(AWS_ACCESS_KEY_ID);
    if (!access_key || strlen(access_key) <= 0) {
        return NULL;
    }

    secret_key = getenv(AWS_SECRET_ACCESS_KEY);
    if (!secret_key || strlen(secret_key) <= 0) {
        return NULL;
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        flb_errno();
        return NULL;
    }

    creds->access_key_id = flb_sds_create(access_key);
    if (!creds->access_key_id) {
        aws_credentials_destroy(creds);
        flb_errno();
        return NULL;
    }

    creds->secret_access_key = flb_sds_create(secret_key);
    if (!creds->secret_access_key) {
        aws_credentials_destroy(creds);
        flb_errno();
        return NULL;
    }

    session_token = getenv(AWS_SESSION_TOKEN);
    if (session_token && strlen(session_token) > 0) {
        creds->session_token = flb_sds_create(session_token);
        if (!creds->session_token) {
            aws_credentials_destroy(creds);
            flb_errno();
            return NULL;
        }
    } else {
        creds->session_token = NULL;
    }

    return creds;

}

/*
 * For the env provider, refresh simply checks if the environment
 * variables are available.
 */
int refresh_fn_environment(struct aws_credentials_provider *provider)
{
    char *access_key;
    char *secret_key;

    flb_debug("[aws_credentials] Refresh called on the env provider");

    access_key = getenv(AWS_ACCESS_KEY_ID);
    if (!access_key || strlen(access_key) <= 0) {
        return -1;
    }

    secret_key = getenv(AWS_SECRET_ACCESS_KEY);
    if (!secret_key || strlen(secret_key) <= 0) {
        return -1;
    }

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
    struct aws_credentials_provider *provider = flb_calloc(1,
                                                          sizeof(
                                                          struct
                                                          aws_credentials_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &environment_provider_vtable;
    provider->implementation = NULL;

    return provider;
}

/*
 * HTTP Credentials Provider - retrieve credentials from a local http server
 * Used to implement the ECS Credentials provider.
 * Equivalent to:
 * https://github.com/aws/aws-sdk-go/tree/master/aws/credentials/endpointcreds
 */

struct aws_credentials_provider_http {
    struct aws_credentials *creds;
    time_t next_refresh;

    struct aws_http_client *client;

    /* Host and Path to request credentials */
    flb_sds_t host;
    flb_sds_t path;
};

struct aws_credentials *get_credentials_fn_http(struct aws_credentials_provider
                                                *provider)
{
    struct aws_credentials *creds;
    int ret;
    int refresh = FLB_FALSE;
    struct aws_credentials_provider_http *implementation = provider->
                                                           implementation;

    flb_debug("[aws_credentials] Retrieving credentials from the "
              "HTTP provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        ret = http_credentials_request(implementation);
        if (ret < 0) {
            return NULL;
        }
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        flb_errno();
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        flb_errno();
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            flb_errno();
            goto error;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_http(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_http *implementation = provider->
                                                           implementation;
    flb_debug("[aws_credentials] Refresh called on the http provider");
    return http_credentials_request(implementation);
}

void destroy_fn_http(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_http *implementation = provider->
                                                           implementation;

    if (implementation) {
        if (implementation->creds) {
            aws_credentials_destroy(implementation->creds);
        }

        if (implementation->client) {
            aws_client_destroy(implementation->client);
        }

        if (implementation->host) {
            flb_sds_destroy(implementation->host);
        }

        if (implementation->path) {
            flb_sds_destroy(implementation->path);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct aws_credentials_provider_vtable http_provider_vtable = {
    .get_credentials = get_credentials_fn_http,
    .refresh = refresh_fn_http,
    .destroy = destroy_fn_http,
};

struct aws_credentials_provider *new_http_provider(struct flb_config *config,
                                                   flb_sds_t host,
                                                   flb_sds_t path,
                                                   struct
                                                   aws_http_client_generator
                                                   *generator)
{
    struct aws_credentials_provider_http *implementation;
    struct aws_credentials_provider *provider;
    struct flb_upstream *upstream;

    provider = flb_calloc(1, sizeof(struct aws_credentials_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct aws_credentials_provider_http));

    if (!implementation) {
        flb_free(provider);
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &http_provider_vtable;
    provider->implementation = implementation;

    implementation->host = host;
    implementation->path = path;

    upstream = flb_upstream_create(config, host, 80, FLB_IO_TCP, NULL);

    if (!upstream) {
        aws_provider_destroy(provider);
        flb_error("[aws_credentials] HTTP Provider: connection initialization "
                  "error");
        return NULL;
    }

    implementation->client = generator->new();
    if (!implementation->client) {
        aws_provider_destroy(provider);
        flb_upstream_destroy(upstream);
        flb_error("[aws_credentials] HTTP Provider: client creation error");
        return NULL;
    }
    implementation->client->name = "http_provider_client";
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

/*
 * ECS Provider
 * The ECS Provider is just a wrapper around the HTTP Provider
 * with the ECS credentials endpoint.
 */

struct aws_credentials_provider *new_ecs_provider(struct flb_config *config,
                                                  struct
                                                  aws_http_client_generator
                                                  *generator)
{
    char *host;
    char *path;
    char *path_var;

    host = flb_malloc((ECS_CREDENTIALS_HOST_LEN + 1) * sizeof(char));
    if (!host) {
        flb_errno();
        return NULL;
    }

    memcpy(host, ECS_CREDENTIALS_HOST, ECS_CREDENTIALS_HOST_LEN);
    host[ECS_CREDENTIALS_HOST_LEN] = '\0';

    path_var = getenv(ECS_CREDENTIALS_PATH_ENV_VAR);
    if (path_var && strlen(path_var) > 0) {
        path = flb_malloc((strlen(path_var) + 1) * sizeof(char));
        if (!path) {
            flb_errno();
            flb_free(host);
            return NULL;
        }
        memcpy(path, path_var, strlen(path_var));
        path[strlen(path_var)] = '\0';

        return new_http_provider(config, host, path, generator);
    } else {
        flb_debug("[aws_credentials] Not initializing ECS Provider because"
                  " %s is not set", ECS_CREDENTIALS_PATH_ENV_VAR);
        return NULL;
    }

}

static int http_credentials_request(struct aws_credentials_provider_http
                                    *implementation)
{
    char *response;
    size_t response_len;
    time_t expiration;
    struct aws_credentials *creds;
    struct aws_http_client *client = implementation->client;
    int ret;

    /* destroy existing credentials */
    aws_credentials_destroy(implementation->creds);

    ret = client->client_vtable->request(client, FLB_HTTP_GET,
                                         implementation->path, NULL, 0,
                                         NULL, 0);

    if (ret != 0 || client->c->resp.status != 200) {
        return -1;
    }

    response = client->c->resp.payload;
    response_len = client->c->resp.payload_size;

    creds = process_http_credentials_response(response, response_len,
                                              &expiration);
    if (!creds) {
        return -1;
    }

    implementation->creds = creds;
    implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
    return 0;
}

/*
 * All HTTP credentials endpoints (IMDS, ECS, custom) follow the same spec:
 * {
 *   "AccessKeyId": "ACCESS_KEY_ID",
 *   "Expiration": "2019-12-18T21:27:58Z",
 *   "SecretAccessKey": "SECRET_ACCESS_KEY",
 *   "Token": "SECURITY_TOKEN_STRING"
 * }
 * (some implementations (IMDS) have additional fields)
 * Returns NULL if any part of parsing was unsuccessful.
 */
struct aws_credentials *process_http_credentials_response(char *response,
                                                          size_t response_len,
                                                          time_t *expiration)
{
    jsmntok_t *tokens = NULL;
    const jsmntok_t *t = NULL;
    char *current_token = NULL;
    jsmn_parser parser;
    int tokens_size = 50;
    size_t size;
    int ret;
    struct aws_credentials *creds = NULL;
    int i = 0;
    int len;
    flb_sds_t tmp = NULL;

    /*
     * Remove/reset existing value of expiration.
     * Expiration should be in the response, but it is not
     * strictly speaking needed. Fluent Bit logs a warning if it is missing.
     */
    *expiration = -1;

    jsmn_init(&parser);

    size = sizeof(jsmntok_t) * tokens_size;
    tokens = flb_calloc(1, size);
    if (!tokens) {
        goto error;
    }

    ret = jsmn_parse(&parser, response, response_len,
                     tokens, tokens_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_error("[aws_credentials] Could not parse http credentials response"
                  " - invalid JSON.");
        goto error;
    }

    /* Shouldn't happen, but just in case, check for too many tokens error */
    if (ret == JSMN_ERROR_NOMEM) {
        flb_error("[aws_credentials] Could not parse http credentials response"
                  " - response contained more tokens than expected.");
        goto error;
    }

    /* return value is number of tokens parsed */
    tokens_size = ret;

    creds = flb_calloc(1, sizeof(struct aws_credentials));
    if (!creds) {
        flb_errno();
        goto error;
    }

    /*
     * jsmn will create an array of tokens like:
     * key, value, key, value
     */
    while (i < (tokens_size - 1)) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type == JSMN_STRING) {
            current_token = &response[t->start];
            len = t->end - t->start;

            if (strncmp(current_token, AWS_HTTP_RESPONSE_ACCESS_KEY, len) == 0)
            {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                creds->access_key_id = flb_sds_create_len(current_token, len);
                if (!creds->access_key_id) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            if (strncmp(current_token, AWS_HTTP_RESPONSE_SECRET_KEY, len) == 0)
            {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                creds->secret_access_key = flb_sds_create_len(current_token,
                                                              len);
                if (!creds->secret_access_key) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            if (strncmp(current_token, AWS_HTTP_RESPONSE_TOKEN, len) == 0) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                creds->session_token = flb_sds_create_len(current_token, len);
                if (!creds->session_token) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            if (strncmp(current_token, AWS_HTTP_RESPONSE_EXPIRATION, len) == 0)
            {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                tmp = flb_sds_create_len(current_token, len);
                if (!tmp) {
                    flb_errno();
                    goto error;
                }
                *expiration = credential_expiration(tmp);
                flb_sds_destroy(tmp);
                if (*expiration < 0) {
                    flb_warn("[aws_credentials] '%s' was invalid or "
                             "could not be parsed. Disabling auto-refresh of "
                             "credentials.", AWS_HTTP_RESPONSE_EXPIRATION);
                }
            }
        }

        i++;
    }

    flb_free(tokens);

    if (creds->access_key_id == NULL) {
        flb_error("[aws_credentials] Missing %s field in http"
                  "credentials response", AWS_HTTP_RESPONSE_ACCESS_KEY);
        goto error;
    }

    if (creds->secret_access_key == NULL) {
        flb_error("[aws_credentials] Missing %s field in http"
                  "credentials response", AWS_HTTP_RESPONSE_SECRET_KEY);
        goto error;
    }

    if (creds->session_token == NULL) {
        flb_error("[aws_credentials] Missing %s field in http"
                  "credentials response", AWS_HTTP_RESPONSE_TOKEN);
        goto error;
    }

    return creds;

error:
    aws_credentials_destroy(creds);
    flb_free(tokens);
    return NULL;
}


void aws_credentials_destroy(struct aws_credentials *creds)
{
    if (creds) {
        if (creds->access_key_id) {
            flb_sds_destroy(creds->access_key_id);
        }
        if (creds->secret_access_key) {
            flb_sds_destroy(creds->secret_access_key);
        }
        if (creds->secret_access_key) {
            flb_sds_destroy(creds->session_token);
        }

        flb_free(creds);
    }
}

void aws_provider_destroy(struct aws_credentials_provider *provider)
{
    if (provider) {
        if (provider->implementation) {
            provider->provider_vtable->destroy(provider);
        }

        flb_free(provider);
    }
}

time_t timestamp_to_epoch(const char *timestamp)
{
    struct tm tm = {0};
    time_t seconds;
    int r;

    r = sscanf(timestamp, "%d-%d-%dT%d:%d:%dZ", &tm.tm_year, &tm.tm_mon,
               &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if (r != 6) {
        return -1;
    }

    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    seconds = timegm(&tm);
    if (seconds < 0) {
        return -1;
    }

    return seconds;
}

time_t credential_expiration(const char *timestamp)
{
    time_t now;
    time_t expiration = timestamp_to_epoch(timestamp);
    if (expiration < 0) {
        flb_warn("[aws_credentials] Could not parse expiration: %s", timestamp);
        return -1;
    }
    /*
     * Sanity check - expiration should be ~10 minutes to 12 hours in the future
     * < 10 minutes is problematic because the provider auto-refreshes if creds
     * expire in 5 minutes. Disabling auto-refresh reduces requests for creds.
     * (The aws_http_client will still force a refresh of creds and then retry
     * if it receives an auth error).
     * (> 12 hours is impossible with the current APIs and would likely indicate
     *  a bug in how this code processes timestamps.)
     */
     now = time(NULL);
     if (expiration < (now + TEN_MINUTES)) {
         flb_warn("[aws_credentials] Credential expiration '%s' is less than"
                  "10 minutes in the future. Disabling auto-refresh.",
                  timestamp);
         return -1;
     }
     if (expiration > (now + TWELVE_HOURS)) {
         flb_warn("[aws_credentials] Credential expiration '%s' is greater than"
                  "12 hours in the future. This should not be possible.",
                  timestamp);
     }
     return expiration;
}

int file_to_buf(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf;
    FILE *fp;
    struct stat st;

    ret = stat(path, &st);
    if (ret == -1) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    buf = flb_malloc(st.st_size + sizeof(char));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes != 1) {
        flb_errno();
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    /* fread does not add null byte */
    buf[st.st_size] = '\0';

    fclose(fp);
    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}
