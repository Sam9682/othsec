#ifdef HAVE_LWS_CONFIG_H
#include "lws_config.h"
#endif

#ifndef TTYD_VERSION
#define TTYD_VERSION "unknown"
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

#ifdef __OpenBSD__
#define STAILQ_HEAD            SIMPLEQ_HEAD
#define STAILQ_ENTRY           SIMPLEQ_ENTRY
#define STAILQ_INIT            SIMPLEQ_INIT
#define STAILQ_INSERT_TAIL     SIMPLEQ_INSERT_TAIL
#define STAILQ_EMPTY           SIMPLEQ_EMPTY
#define STAILQ_FIRST           SIMPLEQ_FIRST
#define STAILQ_REMOVE_HEAD     SIMPLEQ_REMOVE_HEAD
#define STAILQ_FOREACH         SIMPLEQ_FOREACH
#endif

#if defined(__OpenBSD__) || defined(__APPLE__)
#include <util.h>
#elif defined(__FreeBSD__)
#include <libutil.h>
#else
#include <pty.h>
#endif

#include <libwebsockets.h>
#include <json.h>

#include "utils.h"

// client message
#define INPUT '0'
#define PING '1'
#define RESIZE_TERMINAL '2'
#define JSON_DATA '{'

// server message
#define OUTPUT '0'
#define PONG '1'
#define SET_WINDOW_TITLE '2'
#define SET_PREFERENCES '3'
#define SET_RECONNECT '4'

// websocket url path
#define WS_PATH1 "/tcpdump"
#define WS_PATH2 "/tail"
#define WS_PATH3 "/sniffer"

#define BUF_SIZE 32000 // 32K


extern volatile bool force_exit;
extern struct lws_context *context;
extern struct othsec_server *server;

enum pty_state {
    STATE_INIT, STATE_READY, STATE_DONE
};

struct tty_client {
    bool running;
    bool initialized;
    bool authenticated;
    char hostname[100];
    char address[50];

    struct lws *wsi;
    struct winsize size;
    char *buffer;
    size_t len;

    int pid;
    int pty;
    int cmd;
    enum pty_state state;
    char pty_buffer[BUF_SIZE];
    ssize_t pty_len;
    pthread_t thread;
    pthread_mutex_t mutex;

    LIST_ENTRY(tty_client) list;
};

struct per_session_data {
	struct lws_spa *spa;
	char result[LWS_PRE + 512];
	int result_len;
	char filename[64];
	long file_length;
    long justAuthenticate; //a flag we'll use know if we have Authenticate or not...
    long justHeader; //a flag we'll use know if we have sent a header or not...
};

struct othsec_server {
    LIST_HEAD(client, tty_client) clients;    // client list
    int client_count;                         // client count
    char *prefs_json;                         // client preferences
    char *credential;                         // encoded basic auth credential
    int reconnect;                            // reconnect timeout
    char *index;                              // custom index.html
    char *command1;                            // full command line
    char *command2;                         // full command line
    char **argv1;                              // command with arguments
    char **argv2;                              // command with arguments
    int sig_code;                             // close signal
    char sig_name[20];                        // human readable signal string
    bool readonly;                            // whether not allow clients to write to the TTY
    bool check_origin;                        // whether allow websocket connection from different origin
    int max_clients;                          // maximum clients to support
    bool once;                                // whether accept only one client and exit on disconnection
    char socket_path[255];                    // UNIX domain socket path
    pthread_mutex_t mutex;
};

extern int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

extern int callback_tty(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

extern int sniffer();
