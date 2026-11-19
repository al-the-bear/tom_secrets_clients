/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Finding the service (protocol.md section 3).
 */
#include <stdio.h>
#include <string.h>

#include "internal.h"

static const char *var(tsm_getenv_fn getenv_fn, void *context, const char *name) {
    const char *v = getenv_fn(name, context);
    return v ? v : "";
}

/* Copies path without trailing separators (all of them when nothing else is
 * left, as the rule keeps the path then). */
static void strip(char *out, size_t size, const char *path, int windows) {
    size_t end = strlen(path);
    while (end > 0 && (path[end - 1] == '/' || (windows && path[end - 1] == '\\'))) {
        end--;
    }
    if (end == 0) {
        end = strlen(path);
    }
    snprintf(out, size, "%.*s", (int)end, path);
}

tsm_error_kind tsm_discover(const char *os, tsm_getenv_fn getenv_fn, void *context, long long uid,
                            tsm_endpoints *out) {
    int windows = strcmp(os, "windows") == 0;
    const char *override = var(getenv_fn, context, "TSM_RUNTIME_DIR");
    char base[1024];
    memset(out, 0, sizeof *out);
    if (*override) {
        strip(out->directory, sizeof out->directory, override, windows);
    } else if (windows) {
        const char *local = var(getenv_fn, context, "LOCALAPPDATA");
        const char *profile = var(getenv_fn, context, "USERPROFILE");
        if (*local) {
            strip(base, sizeof base, local, 1);
        } else if (*profile) {
            char stripped[900];
            strip(stripped, sizeof stripped, profile, 1);
            snprintf(base, sizeof base, "%s\\AppData\\Local", stripped);
        } else {
            return tsm_set_error(TSM_ERR_NOT_RUNNING, "no_runtime_directory", -1,
                                 "the secrets service is not running: no runtime directory can be named");
        }
        snprintf(out->directory, sizeof out->directory, "%.990s\\TomSecretsManager\\run", base);
    } else {
        const char *value = var(getenv_fn, context, strcmp(os, "macos") == 0 ? "TMPDIR" : "XDG_RUNTIME_DIR");
        if (value[0] == '/') {
            strip(base, sizeof base, value, 0);
            snprintf(out->directory, sizeof out->directory, "%.1000s/tsm", base);
        } else {
            snprintf(out->directory, sizeof out->directory, "/tmp/tsm-%lld", uid);
        }
    }
    if (windows) {
        snprintf(out->client_port_file, sizeof out->client_port_file, "%s\\client.port", out->directory);
        snprintf(out->client_token_file, sizeof out->client_token_file, "%s\\client.token", out->directory);
        snprintf(out->admin_port_file, sizeof out->admin_port_file, "%s\\admin.port", out->directory);
    } else {
        snprintf(out->client_socket, sizeof out->client_socket, "%s/client.sock", out->directory);
        snprintf(out->admin_socket, sizeof out->admin_socket, "%s/admin.sock", out->directory);
    }
    return TSM_OK;
}

int tsm_read_port_file(const char *text) {
    size_t n = strlen(text), i;
    long port = 0;
    if (n >= 2 && text[n - 2] == '\r' && text[n - 1] == '\n') {
        n -= 2;
    } else if (n >= 1 && text[n - 1] == '\n') {
        n -= 1;
    }
    if (n == 0 || n > 5 || text[0] == '0') {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (text[i] < '0' || text[i] > '9') {
            return 0;
        }
        port = port * 10 + (text[i] - '0');
    }
    return port <= 65535 ? (int)port : 0;
}
