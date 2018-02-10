#include "server.h"

#define BUF_SIZE 32000 // 32K

volatile bool force_exit = false;
struct lws_context *context;
struct othsec_server *server;

// websocket protocols
static const struct lws_protocols protocols[] = {
        {"http-only", callback_http, sizeof(struct per_session_data), 0},
        {"tty",       callback_tty,  sizeof(struct tty_client), 0},
        {NULL, NULL, 0, 0}
};

// websocket extensions
static const struct lws_extension extensions[] = {
        {"permessage-deflate", lws_extension_callback_pm_deflate, "permessage-deflate"},
        {"deflate-frame",      lws_extension_callback_pm_deflate, "deflate_frame"},
        {NULL, NULL, NULL}
};

// command line options
static const struct option options[] = {
        {"port",         required_argument, NULL, 'p'},
        {"interface",    required_argument, NULL, 'i'},
        {"credential",   required_argument, NULL, 'c'},
        {"uid",          required_argument, NULL, 'u'},
        {"gid",          required_argument, NULL, 'g'},
        {"signal",       required_argument, NULL, 's'},
        {"signal-list",  no_argument,       NULL,  1},
        {"reconnect",    required_argument, NULL, 'r'},
        {"index",        required_argument, NULL, 'I'},
        {"ssl",          no_argument,       NULL, 'S'},
        {"ssl-cert",     required_argument, NULL, 'C'},
        {"ssl-key",      required_argument, NULL, 'K'},
        {"ssl-ca",       required_argument, NULL, 'A'},
        {"readonly",     no_argument,       NULL, 'R'},
        {"check-origin", no_argument,       NULL, 'O'},
        {"max-clients",  required_argument, NULL, 'm'},
        {"once",         no_argument,       NULL, 'o'},
        {"browser",      no_argument,       NULL, 'B'},
        {"debug",        required_argument, NULL, 'd'},
        {"version",      no_argument,       NULL, 'v'},
        {"help",         no_argument,       NULL, 'h'},
        {NULL,           0,                 0,     0}
};
static const char *opt_string = "p:i:c:u:g:s:r:I:aSC:K:A:Rz:Om:oBd:vh";

#ifdef __linux__
//const char *TEST_COMMAND1[] = { "./tcpdump", "-c", "1", NULL };
const char *TEST_COMMAND1 = "./tcpdump -c 1";
const char *DEFAULT_COMMAND1[] = { "./tcpdump", "-ttl", "(ip)", "and", "(not", "(broadcast", "or", "multicast)", "and", "not", "(port", "514)", "and", "not", "(src", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)", "and", "dst", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)))", NULL };
const char *TEST_COMMAND2 = "tail -0";
const char *DEFAULT_COMMAND2[] = { "tail", "-f", "/var/log/auth.log", NULL };
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
const char *TEST_COMMAND1[] = { "tcpdump.exe", "-c", "1", NULL };
const char *DEFAULT_COMMAND1[] = { "tcpdump.exe", "-ttl", "(ip)", "and", "(not", "(broadcast", "or", "multicast)", "and", "not", "(port", "514)", "and", "not", "(src", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)", "and", "dst", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)))", NULL };
const char *TEST_COMMAND2 = "wevtutil -0";
const char *DEFAULT_COMMAND2[] = { "wevtutil", "qe", "Application", "/f:text", NULL };
#endif

const char *DEFAULT_COMMAND_LIGHT = "/usr/sbin/tcpdump";
const char *DEFAULT_OPTIONS = "-p 8888";


void print_help() {
    fprintf(stderr, "othsec is a tool for monitoring network interface over the web\n\n"
                    "USAGE:\n"
                    "    othsec [options] <command> [<arguments...>]\n\n"
                    "VERSION:\n"
                    "    %s\n\n"
                    "OPTIONS:\n"
                    "    -p, --port              Port to listen (default: 7681, use `0` for random port)\n"
                    "    -i, --interface         Network interface to bind (eg: eth0), or UNIX domain socket path (eg: /var/run/othsec.sock)\n"
                    "    -c, --credential        Credential for Basic Authentication (format: username:password)\n"
                    "    -u, --uid               User id to run with\n"
                    "    -g, --gid               Group id to run with\n"
                    "    -s, --signal            Signal to send to the command when exit it (default: 9, SIGHUP)\n"
                    "    -r, --reconnect         Time to reconnect for the client in seconds (default: 10)\n"
                    "    -R, --readonly          Do not allow clients to write to the TTY\n"
                    "    -z, --client-option     Send option to client (format: key=value), repeat to add more options\n"
                    "    -O, --check-origin      Do not allow websocket connection from different origin\n"
                    "    -m, --max-clients       Maximum clients to support (default: 0, no limit)\n"
                    "    -o, --once              Accept only one client and exit on disconnection\n"
                    "    -B, --browser           Open terminal with the default system browser\n"
                    "    -I, --index             Custom index.html path\n"
                    "    -S, --ssl               Enable SSL\n"
                    "    -C, --ssl-cert          SSL certificate file path\n"
                    "    -K, --ssl-key           SSL key file path\n"
                    "    -A, --ssl-ca            SSL CA file path for client certificate verification\n"
                    "    -d, --debug             Set log level (default: 7)\n"
                    "    -v, --version           Print the version and exit\n"
                    "    -h, --help              Print this text and exit\n\n"
                    "Visit https://github.com/sle/othsec to get more information and report bugs.\n",
            TTYD_VERSION
    );
}

struct othsec_server *othsec_server_new_default(int argc1, char **argv1, int argc2, char **argv2) 
{
    struct othsec_server *ts;
    size_t cmd_len = 0;
    int cmd_argc = 1;
    char *ptr;
    char **cmd_argv;

    ts = xmalloc(sizeof(struct othsec_server));

    memset(ts, 0, sizeof(struct othsec_server));
    LIST_INIT(&ts->clients);
    ts->client_count = 0;
    ts->reconnect = 10;
    ts->sig_code = SIGHUP;
    get_sig_name(ts->sig_code, ts->sig_name, sizeof(ts->sig_name));

    cmd_argc = argc1 - 1;
    cmd_argv = &argv1[1];
    ts->argv1 = xmalloc(sizeof(char *) * (cmd_argc + 1));
    for (int i = 0; i < cmd_argc; i++) {
        ts->argv1[i] = strdup(cmd_argv[i]);
        cmd_len += strlen(ts->argv1[i]);
        if (i != cmd_argc - 1) {
            cmd_len++; // for space
        }
    }
    ts->argv1[cmd_argc] = NULL;

    ts->command1 = xmalloc(cmd_len + 1);
    ptr = ts->command1;
    for (int i = 0; i < cmd_argc; i++) {
        ptr = stpcpy(ptr, ts->argv1[i]);
        if (i != cmd_argc - 1) {
            *ptr++ = ' ';
        }
    }
    *ptr = '\0'; // null terminator

    cmd_argc = argc2 - 1;
    cmd_argv = &argv2[1];
    ts->argv2 = xmalloc(sizeof(char *) * (cmd_argc + 1));
    for (int i = 0; i < cmd_argc; i++) {
        ts->argv2[i] = strdup(cmd_argv[i]);
        cmd_len += strlen(ts->argv2[i]);
        if (i != cmd_argc - 1) {
            cmd_len++; // for space
        }
    }
    ts->argv2[cmd_argc] = NULL;

    ts->command2 = xmalloc(cmd_len + 1);
    ptr = ts->command2;
    for (int i = 0; i < cmd_argc; i++) {
        ptr = stpcpy(ptr, ts->argv2[i]);
        if (i != cmd_argc - 1) {
            *ptr++ = ' ';
        }
    }
    *ptr = '\0'; // null terminator

    return ts;
}

struct othsec_server *othsec_server_new(int argc, char **argv, int start) 
{
    struct othsec_server *ts;
    size_t cmd_len = 0;

    ts = xmalloc(sizeof(struct othsec_server));

    memset(ts, 0, sizeof(struct othsec_server));
    LIST_INIT(&ts->clients);
    ts->client_count = 0;
    ts->reconnect = 10;
    ts->sig_code = SIGHUP;
    get_sig_name(ts->sig_code, ts->sig_name, sizeof(ts->sig_name));
    if (start == argc)
        return ts;

    int cmd_argc = argc - start;
    char **cmd_argv1 = &argv[start];
    ts->argv1 = xmalloc(sizeof(char *) * (cmd_argc + 1));
    for (int i = 0; i < cmd_argc; i++) {
        ts->argv1[i] = strdup(cmd_argv1[i]);
        cmd_len += strlen(ts->argv1[i]);
        if (i != cmd_argc - 1) {
            cmd_len++; // for space
        }
    }
    ts->argv1[cmd_argc] = NULL;

    ts->command1 = xmalloc(cmd_len + 1);
    char *ptr = ts->command1;
    for (int i = 0; i < cmd_argc; i++) {
        ptr = stpcpy(ptr, ts->argv1[i]);
        if (i != cmd_argc - 1) {
            *ptr++ = ' ';
        }
    }
    *ptr = '\0'; // null terminator

    return ts;
}

bool file_exist(char *the_file) 
{
	FILE *fp;
	bool file_exist=FALSE;

	// fopen won't work on "r" mode if file doesn't exist
	fp = fopen(the_file,"r");

	if(fp == NULL){
    	// File doesn't exist
		file_exist = FALSE;
	}else{
    	// File does exist
		file_exist = TRUE;
	}

    return file_exist;
}

void othsec_server_free(struct othsec_server *ts) 
{
    if (ts == NULL)
        return;
    if (ts->credential != NULL)
        free(ts->credential);
    if (ts->index != NULL)
        free(ts->index);
    free(ts->command1);
    free(ts->command2);
    free(ts->prefs_json);
    int i = 0;
    do {
        free(ts->argv1[i++]);
    } while (ts->argv1[i] != NULL);
    i = 0;
    do {
        free(ts->argv2[i++]);
    } while (ts->argv2[i] != NULL);
    free(ts->argv1);
    free(ts->argv2);
    if (strlen(ts->socket_path) > 0) {
        struct stat st;
        if (!stat(ts->socket_path, &st)) {
            unlink(ts->socket_path);
        }
    }
    pthread_mutex_destroy(&ts->mutex);
    free(ts);
}

void sig_handler(int sig) 
{
    if (force_exit)
        exit(EXIT_FAILURE);

    char sig_name[20];
    get_sig_name(sig, sig_name, sizeof(sig_name));
    lwsl_notice("received signal: %s (%d), exiting...\n", sig_name, sig);
    force_exit = true;
    lws_cancel_service(context);
    lwsl_notice("send ^C to force exit.\n");
}

int calc_command_start(int argc, char **argv) 
{
    // make a copy of argc and argv
    int argc_copy = argc;
    char **argv_copy = xmalloc(sizeof(char *) * argc);
    for (int i = 0; i < argc; i++) {
        argv_copy[i] = strdup(argv[i]);
    }

    // do not print error message for invalid option
    opterr = 0;
    while (getopt_long(argc_copy, argv_copy, opt_string, options, NULL) != -1)
        ;

    int start = argc;
    if (optind < argc) {
        char *command = argv_copy[optind];
        for (int i = 0; i < argc; i++) {
            if (strcmp(argv[i], command) == 0) {
                start = i;
                break;
            }
        }
    }

    // free argv copy
    for (int i = 0; i < argc; i++) {
        free(argv_copy[i]);
    }
    free(argv_copy);

    // reset for next use
    opterr = 1;
    optind = 0;

    return start;
}

int main(int argc, char **argv) 
{
int start = 0;
int i1 = 0;
int i2 = 0;
int argc1 = 0;
int argc2 = 0;
int j = 0;
int rc;
int c;
char *TheCommand1[256];
char *TheCommand2[256];
char **newv1 = malloc((argc + 2) * sizeof(*newv1));
char **newv2 = malloc((argc + 2) * sizeof(*newv2));
char cwd[512];
struct lws_context_creation_info info;
int debug_level = LLL_ERR | LLL_WARN | LLL_NOTICE;
char iface[128] = "";
bool browser = false;
bool ssl = false;
char cert_path[1024] = "";
char key_path[1024] = "";
char ca_path[1024] = "";
struct json_object *client_prefs = json_object_new_object();
        
        
        fprintf(stdout, "*******************************************************************************\n");
        fprintf(stdout, "* OTHSEC is a free security tool that snif all Internet TCP trafic of your PC *\n");
        fprintf(stdout, "*  and send all trafic to beewoo.ddns.net plateforme that will analyse it     *\n");
        fprintf(stdout, "*  using an Artificial Intelligent algorithm to see the risk you are facing   *\n");
        fprintf(stdout, "*  while browsing the web.                                                    *\n");
        fprintf(stdout, "* - everything is transparent, and you have to connect to the BEEWOO PLTF     *\n");
        fprintf(stdout, "* - ©ELITELCO 2018 - www.elitelco.net                                         *\n");
        fprintf(stdout, "*******************************************************************************\n");

        // get local folder where OTHSEC is executed
        if (getcwd(cwd, sizeof(cwd)) != NULL)
        {
                i1 = 0;
                while( DEFAULT_COMMAND1[i1] != NULL)
                {
                        TheCommand1[i1] = strdup( (const char *) DEFAULT_COMMAND1[i1]);
                        //fprintf(stdout, "Current command argv : %s \n", (char *)TheCommand[i]);
                        i1++;
                }
                i2 = 0;
                while( DEFAULT_COMMAND2[i2] != NULL)
                {
                        TheCommand2[i2] = strdup( (const char *) DEFAULT_COMMAND2[i2]);
                        //fprintf(stdout, "Current command argv : %s \n", (char *)TheCommand2[i]);
                        i2++;
                }

        }
        else
        {
                perror("getcwd() error");
                return -1;
        }

        // if no argument is passed to OTHSEC, then use default commands TCPDUMP and TAIL
        if (argc == 1)
        {
                char **newv1 = malloc((argc + i1 + 1) * sizeof(*newv1));
                char **newv2 = malloc((argc + i2 + 1) * sizeof(*newv2));

                // Error check omitted
                memmove(newv1, argv, sizeof(*newv1) * argc);
                memmove(newv2, argv, sizeof(*newv2) * argc);

                j = 0;
                argc1 = argc2 = 1;
                while( j < i1 )
                {
                        newv1[argc1++] = TheCommand1[j];
                        //fprintf(stdout, "Current command newv : %s \n", (char *)newv[argc-1]);
                        j++;
                }
                newv1[argc1] = 0;

                j = 0;
                while( j < i2 )
                {
                        newv2[argc2++] = TheCommand2[j];
                        //fprintf(stdout, "Current command newv : %s \n", (char *)newv[argc-1]);
                        j++;
                }

                newv2[argc2] = 0;

                server = othsec_server_new_default(argc1, newv1, argc2, newv2);
        }
        else
        {
                start = calc_command_start(argc, argv);
                server = othsec_server_new(argc, argv, start);
        }

        fprintf(stdout, "-------------------------------------------------------------------------------\n");
        fprintf(stdout, "| Checking environment for proper execution (tools like TCPDUMP & TAIL)       |\n");
        fprintf(stdout, "| This tool is now waiting for a TCP packet on your Net interfaces ...        |\n");
        fprintf(stdout, "-------------------------------------------------------------------------------\n");

        rc = system(TEST_COMMAND1);
        if ( rc < 0) 
        {
                lwsl_err("othsec: EXECVP TCPDUMP ERROR return code = %d ...\n", rc);
                perror("othsec: tool TCPDUMP cannot be executed on this computer ! Please install tool ...\n");
                return -1;
        }

        rc = system(TEST_COMMAND2);
        if (rc < 0) 
        {
                lwsl_err("othsec: EXECVP TAIL ERROR return code = %d ...\n", rc);
                perror("othsec: tool TAIL cannot be executed on this computer ! Please install tool ...\n");
                return -1;
        }
        
        fprintf(stdout, "-------------------------------------------------------------------------------\n");
        fprintf(stdout, "| Environment OK: ready to launch sniffers and get ready to get wet ! :)      |\n");
        fprintf(stdout, "| Now open a webbrowser and get https://beewoo.fddns.net to see your trafic   |\n");
        fprintf(stdout, "-------------------------------------------------------------------------------\n");
        pthread_mutex_init(&server->mutex, NULL);

        memset(&info, 0, sizeof(info));
        info.port = 20508;
        info.iface = NULL;
        info.protocols = protocols;
        info.ssl_cert_filepath = NULL;
        info.ssl_private_key_filepath = NULL;
        info.gid = -1;
        info.uid = -1;
        info.max_http_header_pool = 16;
        info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;
        info.extensions = extensions;
        info.timeout_secs = 5;



        // parse command line options
        while ((c = getopt_long(start, argv, opt_string, options, NULL)) != -1) 
        {
                switch (c) 
                {
                    case 'h':
                        print_help();
                        return 0;
                    case 'v':
                        printf("othsec version %s\n", TTYD_VERSION);
                        return 0;
                    case 'd':
                        debug_level = atoi(optarg);
                        break;
                    case 'R':
                        server->readonly = true;
                        break;
                    case 'O':
                        server->check_origin = true;
                        break;
                    case 'm':
                        server->max_clients = atoi(optarg);
                        break;
                    case 'o':
                        server->once = true;
                        break;
                    case 'B':
                        browser = true;
                        break;
                    case 'p':
                        info.port = atoi(optarg);
                        if (info.port < 0) {
                            fprintf(stderr, "othsec: invalid port: %s\n", optarg);
                            return -1;
                        }
                        break;
                    case 'i':
                        strncpy(iface, optarg, sizeof(iface) - 1);
                        iface[sizeof(iface) - 1] = '\0';
                        break;
                    case 'c':
                        if (strchr(optarg, ':') == NULL) {
                            fprintf(stderr, "othsec: invalid credential, format: username:password\n");
                            return -1;
                        }
                        server->credential = base64_encode((const unsigned char *) optarg, strlen(optarg));
                        break;
                    case 'u':
                        info.uid = atoi(optarg);
                        break;
                    case 'g':
                        info.gid = atoi(optarg);
                        break;
                    case 's': {
                        int sig = get_sig(optarg);
                        if (sig > 0) {
                            server->sig_code = sig;
                            get_sig_name(sig, server->sig_name, sizeof(server->sig_code));
                        } else {
                            fprintf(stderr, "othsec: invalid signal: %s\n", optarg);
                            return -1;
                        }
                    }
                        break;
                    case 'r':
                        server->reconnect = atoi(optarg);
                        if (server->reconnect <= 0) {
                            fprintf(stderr, "othsec: invalid reconnect: %s\n", optarg);
                            return -1;
                        }
                        break;
                    case 'I':
                        if (!strncmp(optarg, "~/", 2)) {
                            const char* home = getenv("HOME");
                            server->index = malloc(strlen(home) + strlen(optarg) - 1);
                            sprintf(server->index, "%s%s", home, optarg + 1);
                        } else {
                            server->index = strdup(optarg);
                        }
                        struct stat st;
                        if (stat(server->index, &st) == -1) {
                            fprintf(stderr, "Can not stat index.html: %s, error: %s\n", server->index, strerror(errno));
                            return -1;
                        }
                        if (S_ISDIR(st.st_mode)) {
                            fprintf(stderr, "Invalid index.html path: %s, is it a dir?\n", server->index);
                            return -1;
                        }
                        break;
                    case 'S':
                        ssl = true;
                        break;
                    case 'C':
                        strncpy(cert_path, optarg, sizeof(cert_path) - 1);
                        cert_path[sizeof(cert_path) - 1] = '\0';
                        break;
                    case 'K':
                        strncpy(key_path, optarg, sizeof(key_path) - 1);
                        key_path[sizeof(key_path) - 1] = '\0';
                        break;
                    case 'A':
                        strncpy(ca_path, optarg, sizeof(ca_path) - 1);
                        ca_path[sizeof(ca_path) - 1] = '\0';
                        break;
                    case '?':
                        break;
                    case 'z':
                        optind--;
                        for (; optind < start && *argv[optind] != '-'; optind++) {
                            char *option = strdup(optarg);
                            char *key = strsep(&option, "=");
                            if (key == NULL) {
                                fprintf(stderr, "othsec: invalid client option: %s, format: key=value\n", optarg);
                                return -1;
                            }
                            char *value = strsep(&option, "=");
                            free(option);
                            struct json_object *obj = json_tokener_parse(value);
                            json_object_object_add(client_prefs, key, obj != NULL ? obj : json_object_new_string(value));
                        }
                        break;
                    default:
                        print_help();
                        return -1;
                }
        }

        server->prefs_json = strdup(json_object_to_json_string(client_prefs));
        json_object_put(client_prefs);

        if (server->command1 == NULL || strlen(server->command1) == 0) 
        {
                lwsl_notice(" NULL server-command\n");
                return -1;
        }

        lws_set_log_level(debug_level, NULL);

        #if LWS_LIBRARY_VERSION_MAJOR >= 2
        char server_hdr[128] = "";
        sprintf(server_hdr, "othsec/%s (libwebsockets/%s)", TTYD_VERSION, LWS_LIBRARY_VERSION);
        info.server_string = server_hdr;
        #endif

        if (strlen(iface) > 0) 
        {
                info.iface = iface;
                if (endswith(info.iface, ".sock") || endswith(info.iface, ".socket")) 
                {
                        #if defined(LWS_USE_UNIX_SOCK) || defined(LWS_WITH_UNIX_SOCK)
                        info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
                        strncpy(server->socket_path, info.iface, sizeof(server->socket_path));
                        #else
                        fprintf(stderr, "libwebsockets is not compiled with UNIX domain socket support");
                        return -1;
                        #endif
                }
        }

        if (ssl) 
        {
                info.ssl_cert_filepath = cert_path;
                info.ssl_private_key_filepath = key_path;
                info.ssl_ca_filepath = ca_path;
                info.ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
                        "ECDHE-RSA-AES256-GCM-SHA384:"
                        "DHE-RSA-AES256-GCM-SHA384:"
                        "ECDHE-RSA-AES256-SHA384:"
                        "HIGH:!aNULL:!eNULL:!EXPORT:"
                        "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
                        "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
                        "!DHE-RSA-AES128-SHA256:"
                        "!AES128-GCM-SHA256:"
                        "!AES128-SHA256:"
                        "!DHE-RSA-AES256-SHA256:"
                        "!AES256-GCM-SHA384:"
                        "!AES256-SHA256";
                if (strlen(info.ssl_ca_filepath) > 0)
                    info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
                #if LWS_LIBRARY_VERSION_MAJOR >= 2
                info.options |= LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;
                #endif
        }

        lwsl_notice("OTHSEC %s (libwebsockets %s)\n", TTYD_VERSION, LWS_LIBRARY_VERSION);
        lwsl_notice("OTHSEC configuration:\n");
        if (server->credential != NULL)
        	lwsl_notice("  credential: %s\n", server->credential);
        lwsl_notice("  start command0: %s\n", "sniffer");
        lwsl_notice("  start command1: %s\n", server->command1);
        lwsl_notice("  start command2: %s\n", server->command2);
        lwsl_notice("  reconnect timeout: %ds\n", server->reconnect);
        lwsl_notice("  close signal: %s (%d)\n", server->sig_name, server->sig_code);
        if (server->check_origin)
        lwsl_notice("  check origin: true\n");
        //if (server->readonly)
        //    lwsl_notice("  readonly: true\n");
        //if (server->max_clients > 0)
        //    lwsl_notice("  max clients: %d\n", server->max_clients);
        //if (server->once)
        //    lwsl_notice("  once: true\n");
        //if (server->index != NULL) {
        //    lwsl_notice("  custom index.html: %s\n", server->index);
        //}

        signal(SIGINT, sig_handler);  // ^C
        signal(SIGTERM, sig_handler); // kill

        context = lws_create_context(&info);
        if (context == NULL) {
                lwsl_err("libwebsockets init failed\n");
                return 1;
        }

        if (browser) {
                char url[30];
                sprintf(url, "%s://localhost:%d", ssl ? "https" : "http", info.port);
                open_uri(url);
        }

        // libwebsockets main loop
        while (!force_exit) 
        {
                pthread_mutex_lock(&server->mutex);
                if (!LIST_EMPTY(&server->clients)) 
                {
                        struct tty_client *client;
                        LIST_FOREACH(client, &server->clients, list) 
                        {
                                if (client->running) 
                                {
                                        pthread_mutex_lock(&client->mutex);
                                        if (client->state != STATE_DONE)
                                                lws_callback_on_writable(client->wsi);
                                        pthread_mutex_unlock(&client->mutex);
                                }
                        }
                }
                pthread_mutex_unlock(&server->mutex);
                lws_service(context, 10);
        }


        // cleanup
        lws_context_destroy(context);
        free(newv1);
        free(newv2);
        othsec_server_free(server);

        return 0;
}
