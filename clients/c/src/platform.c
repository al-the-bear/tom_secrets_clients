/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The platform layer: sockets (Unix domain sockets on Linux and macOS,
 * Winsock on Windows), threads, mutexes and condition variables, clocks and
 * files.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#endif

/* ---- Windows --------------------------------------------------------- */
#ifdef _WIN32

static INIT_ONCE winsock_once = INIT_ONCE_STATIC_INIT;
static int winsock_ok;

static BOOL CALLBACK start_winsock(PINIT_ONCE once, PVOID param, PVOID *context) {
    WSADATA data;
    (void)once;
    (void)param;
    (void)context;
    winsock_ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    return TRUE;
}

int tsm_platform_init(void) {
    InitOnceExecuteOnce(&winsock_once, start_winsock, NULL, NULL);
    return winsock_ok;
}

void tsm_mutex_init(tsm_mutex *m) { InitializeSRWLock(m); }
void tsm_mutex_destroy(tsm_mutex *m) { (void)m; }
void tsm_mutex_lock(tsm_mutex *m) { AcquireSRWLockExclusive(m); }
void tsm_mutex_unlock(tsm_mutex *m) { ReleaseSRWLockExclusive(m); }
void tsm_cond_init(tsm_cond *c) { InitializeConditionVariable(c); }
void tsm_cond_destroy(tsm_cond *c) { (void)c; }
void tsm_cond_wait(tsm_cond *c, tsm_mutex *m) { SleepConditionVariableSRW(c, m, INFINITE, 0); }

int tsm_cond_timedwait(tsm_cond *c, tsm_mutex *m, long long timeout_ms) {
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    return SleepConditionVariableSRW(c, m, (DWORD)timeout_ms, 0) ? 0 : 1;
}

void tsm_cond_broadcast(tsm_cond *c) { WakeAllConditionVariable(c); }

typedef struct thread_start {
    void (*fn)(void *);
    void *arg;
} thread_start;

static DWORD WINAPI run_thread(LPVOID p) {
    thread_start s = *(thread_start *)p;
    free(p);
    s.fn(s.arg);
    return 0;
}

int tsm_thread_start(void (*fn)(void *), void *arg) {
    thread_start *s = (thread_start *)malloc(sizeof *s);
    HANDLE h;
    if (!s) {
        return 0;
    }
    s->fn = fn;
    s->arg = arg;
    h = CreateThread(NULL, 0, run_thread, s, 0, NULL);
    if (!h) {
        free(s);
        return 0;
    }
    CloseHandle(h);
    return 1;
}

long long tsm_monotonic_ms(void) { return (long long)GetTickCount64(); }
void tsm_sleep_ms(long long ms) { Sleep((DWORD)ms); }

long long tsm_process_uid(void) { return -1; }

int tsm_socket_connect_unix(const char *path, tsm_socket *out) {
    (void)path;
    (void)out;
    return -1;
}

int tsm_socket_connect_localhost(int port, int timeout_ms, tsm_socket *out) {
    SOCKET s;
    struct sockaddr_in a;
    u_long nonblocking = 1, blocking = 0;
    fd_set write_set, error_set;
    struct timeval tv;
    if (!tsm_platform_init()) {
        return -1;
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ioctlsocket(s, FIONBIO, &nonblocking);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s);
        return -1;
    }
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(s, &write_set);
    FD_SET(s, &error_set);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(0, NULL, &write_set, &error_set, &tv) <= 0 || FD_ISSET(s, &error_set)) {
        closesocket(s);
        return -1;
    }
    ioctlsocket(s, FIONBIO, &blocking);
    *out = s;
    return 0;
}

int tsm_socket_send_all(tsm_socket s, const unsigned char *data, size_t len) {
    while (len > 0) {
        int n = send(s, (const char *)data, len > 1 << 30 ? 1 << 30 : (int)len, 0);
        if (n <= 0) {
            return -1;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

long tsm_socket_recv(tsm_socket s, unsigned char *buffer, size_t size) {
    int n = recv(s, (char *)buffer, (int)size, 0);
    return n < 0 ? -1 : n;
}

void tsm_socket_shutdown(tsm_socket s) { shutdown(s, SD_BOTH); }
void tsm_socket_close(tsm_socket s) { closesocket(s); }

int tsm_file_exists(const char *path) { return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES; }

/* ---- POSIX ----------------------------------------------------------- */
#else

int tsm_platform_init(void) { return 1; }

void tsm_mutex_init(tsm_mutex *m) { pthread_mutex_init(m, NULL); }
void tsm_mutex_destroy(tsm_mutex *m) { pthread_mutex_destroy(m); }
void tsm_mutex_lock(tsm_mutex *m) { pthread_mutex_lock(m); }
void tsm_mutex_unlock(tsm_mutex *m) { pthread_mutex_unlock(m); }
void tsm_cond_init(tsm_cond *c) { pthread_cond_init(c, NULL); }
void tsm_cond_destroy(tsm_cond *c) { pthread_cond_destroy(c); }
void tsm_cond_wait(tsm_cond *c, tsm_mutex *m) { pthread_cond_wait(c, m); }

int tsm_cond_timedwait(tsm_cond *c, tsm_mutex *m, long long timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    ts.tv_sec += (time_t)(timeout_ms / 1000);
    ts.tv_nsec += (long)((timeout_ms % 1000) * 1000000);
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    return pthread_cond_timedwait(c, m, &ts) == ETIMEDOUT ? 1 : 0;
}

void tsm_cond_broadcast(tsm_cond *c) { pthread_cond_broadcast(c); }

typedef struct thread_start {
    void (*fn)(void *);
    void *arg;
} thread_start;

static void *run_thread(void *p) {
    thread_start s = *(thread_start *)p;
    free(p);
    s.fn(s.arg);
    return NULL;
}

int tsm_thread_start(void (*fn)(void *), void *arg) {
    pthread_t t;
    thread_start *s = (thread_start *)malloc(sizeof *s);
    if (!s) {
        return 0;
    }
    s->fn = fn;
    s->arg = arg;
    if (pthread_create(&t, NULL, run_thread, s) != 0) {
        free(s);
        return 0;
    }
    pthread_detach(t);
    return 1;
}

long long tsm_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void tsm_sleep_ms(long long ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)((ms % 1000) * 1000000);
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

long long tsm_process_uid(void) { return (long long)getuid(); }

int tsm_socket_connect_unix(const char *path, tsm_socket *out) {
    struct sockaddr_un a;
    int s;
    if (strlen(path) >= sizeof a.sun_path) {
        return -1;
    }
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        return -1;
    }
#ifdef SO_NOSIGPIPE
    {
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    }
#endif
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, path, strlen(path));
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        close(s);
        return -1;
    }
    *out = s;
    return 0;
}

int tsm_socket_connect_localhost(int port, int timeout_ms, tsm_socket *out) {
    (void)port;
    (void)timeout_ms;
    (void)out;
    return -1;
}

int tsm_socket_send_all(tsm_socket s, const unsigned char *data, size_t len) {
    while (len > 0) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(s, data, len, MSG_NOSIGNAL);
#else
        ssize_t n = send(s, data, len, 0);
#endif
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

long tsm_socket_recv(tsm_socket s, unsigned char *buffer, size_t size) {
    for (;;) {
        ssize_t n = recv(s, buffer, size, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return n < 0 ? -1 : (long)n;
    }
}

void tsm_socket_shutdown(tsm_socket s) { shutdown(s, SHUT_RDWR); }
void tsm_socket_close(tsm_socket s) { close(s); }

int tsm_file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

#endif

char *tsm_read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    tsm_buf b = {NULL, 0, 0};
    unsigned char chunk[4096];
    size_t n;
    if (!f) {
        return NULL;
    }
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
        if (!tsm_buf_add(&b, chunk, n)) {
            fclose(f);
            tsm_buf_wipe(&b);
            return NULL;
        }
    }
    fclose(f);
    tsm_wipe(chunk, sizeof chunk);
    if (!b.data && !tsm_buf_add(&b, "", 0)) {
        return NULL;
    }
    if (len) {
        *len = b.len;
    }
    return (char *)b.data;
}

const char *tsm_current_operating_system(void) {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}
