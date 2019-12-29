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
#include <unistd.h>
#include <ctype.h>

#define ACCESS_KEY_PROPERTY_NAME            "aws_access_key_id"
#define SECRET_KEY_PROPERTY_NAME            "aws_secret_access_key"
#define SESSION_TOKEN_PROPERTY_NAME         "aws_session_token"

#define AWS_PROFILE                         "AWS_PROFILE"
#define AWS_DEFAULT_PROFILE                 "AWS_DEFAULT_PROFILE"

/*
 * A provider that reads from the shared credentials file.
 */
static struct aws_credentials_provider_profile {
    struct aws_credentials *credentials;

    flb_sds_t *profile;
    flb_sds_t *path;
};

aws_credentials *get_credentials_fn_profile(struct aws_credentials_provider
                                         *provider)
{
    aws_credentials *creds;
    int ret;
    struct aws_credentials_provider_profile *implementation = provider->
                                                              implementation;

    flb_debug("[aws_credentials] Retrieving credentials for "
              "AWS Profile %s", implementation->profile);

    if (!implementation->credentials) {
        ret = get_profile(implementation);
        if (ret < 0) {
            return NULL:
        }
    }

    creds = flb_malloc(sizeof(struct aws_credentials));
    if (!creds) {
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->credentials->access_key_id);
    if (!creds->access_key_id) {
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->credentials->secret_access_key);
    if (!creds->secret_access_key) {
        goto error;
    }

    if (implementation->credentials->session_token) {
        creds->session_token = flb_sds_create(implementation->credentials->session_token);
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

int refresh_fn_profile(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_profile *implementation = provider->
                                                              implementation;
    flb_debug("[aws_credentials] Refresh called on the profile provider");
    return get_profile(implementation);
}

void destroy_fn_profile(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_profile *implementation = provider->
                                                              implementation;

    if (implementation) {
        if (implementation->credentials) {
            aws_credentials_destroy(implementation->credentials);
        }

        if (implementation->profile) {
            flb_sds_destroy(implementation->profile);
        }

        if (implementation->path) {
            flb_sds_destroy(implementation->path);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct aws_credentials_provider_vtable profile_provider_vtable = {
    .get_credentials = get_credentials_fn_profile,
    .refresh = refresh_fn_profile,
    .destroy = destroy_fn_profile,
};

struct aws_credentials_provider *new_profile_provider()
{
    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_profile *implementation = NULL;
    char *path;
    char *profile;
    char *home

    provider = flb_calloc(1, sizeof(struct aws_credentials_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1,
                                sizeof(
                                struct aws_credentials_provider_profile));

    if (!implementation) {
        goto error;
    }

    provider->provider_vtable = &profile_provider_vtable;
    provider->implementation = implementation;

    /* find the shared credentials file */
    path = getenv(AWS_SHARED_CREDENTIALS_FILE);
    if (path && strlen(path) > 0) {
        implementation->path = flb_sds_create(path);
    } else {
        /* default path: $HOME/.aws/credentials */
        home = getenv("HOME");
        if (!home || strlen(home) == 0) {
            flb_warn("[aws_credentials] Failed to initialized profile provider: "
            "$HOME not set and AWS_SHARED_CREDENTIALS_FILE not set.");
            aws_provider_destroy(provider);
            return NULL;
        }

        /* join file path */
        implementation->path = flb_sds_create(home);
        if (!implementation->path) {
            goto error;
        }
        if (home[strlen(home) - 1] == '/') {
            implementation->path = flb_sds_cat(implementation->path,
                                               ".aws/credentials", 16);
        } else {
            implementation->path = flb_sds_cat(implementation->path,
                                               "/.aws/credentials", 17);
        }
    }

    if (!implementation->path) {
        goto error;
    }

    /* AWS profile name */
    profile = getenv(AWS_PROFILE);
    if (profile && strlen(profile) > 0) {
        goto set_profile;
    }

    profile = getenv(AWS_DEFAULT_PROFILE);
    if (profile && strlen(profile) > 0) {
        goto set_profile;
    }

    profile = "default";

set_profile:
    implementation->profile = flb_sds_create(profile);
    if (!implementation->profile) {
        goto error;
    }

error:
    flb_errno();
    aws_provider_destroy(provider);
    return NULL;
}

static int file_to_buf(const char *path, char **out_buf, size_t *out_size)
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

static int is_profile_line(char *line) {
    if (strlen(line) > 1 && line[0] == '[') {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* Called on lines that have is_profile_line == True */
static int has_profile(char *line, char* profile) {
    char *end_bracket = strchr(line, ']');
    if (!end_bracket) {
        flb_warn("[aws_credentials] Profile header has no ending bracket:\n %s",
                 line);
        return FLB_FALSE;
    }
    *end_bracket = '\0';

    if (strcmp(&line[1], profile) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Sets a null byte such that line becomes the property name
 * Returns a pointer to the rest of the line (the value), if successful.
 */
static char *parse_property_line(char *line) {
    int len = strlen(line);

    if (isspace(line[0])) {
        /* property line can not start with whitespace */
        return NULL;
    }

    for (int i=0; i < (len - 1); i++) {
        if (isspace(line[i]) || line[i] == '=') {
            line[i] = '\0';
            return &line[i + 1];
        }
    }

    return NULL
}

/* called on the rest of a line after parse_property_line is called */
static flb_sds_t parse_property_value(char *s) {
    int len = strlen(s);
    int i = 0;
    char *val = NULL;
    flb_sds_t prop;

    for (int i=0; i < len; i++) {
        if (isspace(s[i]) || s[i] == '=') {
            s[i] = '\0';
            continue;
        } else if (!val) {
            val = &s[i];
        }
    }

    prop = flb_sds_create(val);
    if (!prop) {
        flb_errno();
        return NULL;
    }

    return prop;
}

/*
 * Parses a shared credentials file.
 * Expects the contents of 'creds' to be initialized to NULL.
 */
static int parse_file(char *buf, char *profile, struct aws_credentials *creds)
{
    char *line;
    char *line_end;
    char *prop_val = NULL;
    int found_profile = FLB_FALSE;

    line = buf;

    while (line[0] != '\0') {
        /* turn the line into a C string */
        line_end = strchr(line, '\n');
        if (line_end) {
            *line_end = '\0';
        }

        prop_val = parse_property_line(line);

        if (is_profile_line(line) == FLB_TRUE) {
            if (found_profile == FLB_TRUE) {
                break;
            }
            if (has_profile(line, profile)) {
                found_profile = FLB_TRUE;
            }
        } else if (prop_val && found_profile == FLB_TRUE) {
            if (strcmp(line, ACCESS_KEY_PROPERTY_NAME)) {
                creds->access_key_id = parse_property_value(prop_val);
            }
            if (strcmp(line, SECRET_KEY_PROPERTY_NAME)) {
                creds->secret_access_key = parse_property_value(prop_val);
            }
            if (strcmp(line, SESSION_TOKEN_PROPERTY_NAME)) {
                creds->session_token = parse_property_value(prop_val);
            }
        }

        /* advance to next line */
        if (line_end) {
            line = line_end + 1;
        } else {
            break;
        }
    }

    if (creds->access_key_id && creds->secret_access_key) {
        return 0;
    }
    return -1;
}

static int get_profile(aws_credentials_provider_profile
                                           *implementation)
{
    struct aws_credentials *creds;
    int ret;
    char* buf;
    size_t size;

    creds = flb_calloc(1, sizeof(struct aws_credentials));
    if (!creds) {
        flb_errno();
        return -1;
    }

    ret = file_to_buf(implementation->path, &buf, &size);
    if (ret < 0) {
        flb_error("[aws_credentials] Could not read shared credentials file %s",
                  implementation->path);
        goto error;
    }

    ret = parse_file(buf, implementation->profile, creds);
    flb_free(buf);

    if (ret < 0) {
        flb_error("[aws_credentials] Could not parse shared credentials file: "
                  "valid profile with name '%s' not found",
                  implementation->profile);
        goto error;
    }

    implementation->credentials = creds;

error:
    aws_credentials_destroy(creds);
    return -1;
}
