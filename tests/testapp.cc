/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <evutil.h>
#include <snappy-c.h>
#include <gtest/gtest.h>

#include <atomic>
#include <algorithm>
#include <string>
#include <vector>

#include "testapp.h"
#include "testapp_subdoc.h"

#include <memcached/util.h>
#include <memcached/config_parser.h>
#include <cbsasl/cbsasl.h>
#include "extensions/protocol/testapp_extension.h"
#include <platform/platform.h>
#include "memcached/openssl.h"
#include "programs/utilities.h"
#include "utilities/protocol2text.h"

#ifdef WIN32
#include <process.h>
#define getpid() _getpid()
#endif


/* Set the read/write commands differently than the default values
 * so that we can verify that the override works
 */
static uint8_t read_command = 0xe1;
static uint8_t write_command = 0xe2;

char *config_string = NULL;
#define CFG_FILE_PATTERN "memcached_testapp.json.XXXXXX"
char config_file[] = CFG_FILE_PATTERN;
#define RBAC_FILE_PATTERN "testapp_rbac.json.XXXXXX"
char rbac_file[] = RBAC_FILE_PATTERN;

/* engine types */
#define BLOCK_ENGINE "ewouldblock_engine.so"
#define DEFAULT_ENGINE "default_engine.so"
#define BUCKET_ENGINE "bucket_engine.so"

#define MAX_CONNECTIONS 1000
#define BACKLOG 1024

/* test phases (bitmasks) */
#define phase_plain 0x2
#define phase_ssl 0x4

#define phase_max 4
static int current_phase = 0;

static pid_t server_pid;
in_port_t port = -1;
static in_port_t ssl_port = -1;
SOCKET sock;
static SOCKET sock_ssl;
static std::atomic_bool allow_closed_read;
static time_t server_start_time = 0;
static SSL_CTX *ssl_ctx = NULL;
static SSL *ssl = NULL;
static BIO *ssl_bio_r = NULL;
static BIO *ssl_bio_w = NULL;

bool memcached_verbose = false;

/* static storage for the different environment variables set by
 * putenv().
 *
 * (These must be static as putenv() essentially 'takes ownership' of
 * the provided array, so it is unsafe to use an automatic variable.
 * However, if we use the result of malloc() (i.e. the heap) then
 * memory leak checkers (e.g. Valgrind) will report the memory as
 * leaked as it's impossible to free it).
 */
static char topkeys_count_env[80];
static char mcd_parent_monitor_env[80];
static char mcd_port_filename_env[80];
static char isasl_pwfile_env[1024];

static void stop_memcached_server(void);
static SOCKET connect_to_server_ssl(in_port_t ssl_port, bool nonblocking);

static void destroy_ssl_socket();

static void set_mutation_seqno_feature(bool enable);

std::ostream& operator << (std::ostream& os, const Transport& t)
{
    switch (t) {
    case Transport::Plain:
        os << "Transport::Plain";
        break;
    case Transport::SSL:
        os << "Transport::SSL";
        break;
    }
    return os;
}

void McdTestappTest::CreateTestBucket()
{
    // We need to create the bucket
    int phase = current_phase;
    current_phase = phase_plain;

    sock = connect_to_server_plain(port, false);
    ASSERT_EQ(PROTOCOL_BINARY_RESPONSE_SUCCESS, sasl_auth("_admin",
                                                          "password"));
    union {
        protocol_binary_request_create_bucket request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    char cfg[80];
    memset(cfg, 0, sizeof(cfg));
    snprintf(cfg, sizeof(cfg), "ewouldblock_engine.so%cdefault_engine.so",
             0);

    size_t plen = raw_command(buffer.bytes, sizeof(buffer.bytes),
                              PROTOCOL_BINARY_CMD_CREATE_BUCKET,
                              "mybucket", strlen("mybucket"),
                              cfg, sizeof(cfg));


    safe_send(buffer.bytes, plen, false);
    safe_recv_packet(&buffer, sizeof(buffer));

    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_CREATE_BUCKET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    closesocket(sock);
    sock = INVALID_SOCKET;

    current_phase = phase;
}

// Per-test-case set-up.
// Called before the first test in this test case.
void McdTestappTest::SetUpTestCase() {
    cJSON *config = generate_config();
    start_memcached_server(config);
    cJSON_Delete(config);

    if (HasFailure()) {
        server_pid = reinterpret_cast<pid_t>(-1);
    } else {
        CreateTestBucket();
    }
}

// Per-test-case tear-down.
// Called after the last test in this test case.
void McdTestappTest::TearDownTestCase() {
    closesocket(sock);

    if (server_pid != reinterpret_cast<pid_t>(-1)) {
        current_phase = phase_plain;
        sock = connect_to_server_plain(port, false);
        ASSERT_EQ(PROTOCOL_BINARY_RESPONSE_SUCCESS, sasl_auth("_admin",
                                                              "password"));
        union {
            protocol_binary_request_delete_bucket request;
            protocol_binary_response_no_extras response;
            char bytes[1024];
        } buffer;

        size_t plen = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                  PROTOCOL_BINARY_CMD_DELETE_BUCKET,
                                  "mybucket", strlen("mybucket"),
                                  NULL, 0);

        safe_send(buffer.bytes, plen, false);
        safe_recv_packet(&buffer, sizeof(buffer));

        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_DELETE_BUCKET,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }
    shutdown_openssl();
    stop_memcached_server();
}

// per test setup function.
void McdTestappTest::SetUp() {
    ASSERT_NE(reinterpret_cast<pid_t>(-1), server_pid);
    if (GetParam() == Transport::Plain) {
        current_phase = phase_plain;
        sock = connect_to_server_plain(port, false);
        ASSERT_NE(INVALID_SOCKET, sock);
    } else {
        current_phase = phase_ssl;
        sock_ssl = connect_to_server_ssl(ssl_port, false);
        ASSERT_NE(INVALID_SOCKET, sock_ssl);
    }

    ASSERT_EQ(PROTOCOL_BINARY_RESPONSE_SUCCESS, sasl_auth("mybucket",
                                                          "mybucketpassword"));

    // Set ewouldblock_engine test harness to default mode.
    ewouldblock_engine_configure(ENGINE_EWOULDBLOCK, EWBEngineMode_FIRST,
                                 /*unused*/0);
}

// per test tear-down function.
void McdTestappTest::TearDown() {
    if (GetParam() == Transport::Plain) {
        closesocket(sock);
    } else {
        closesocket(sock_ssl);
        destroy_ssl_socket();
    }
}

void McdBucketTest::SetUpTestCase() {
    cJSON *config = generate_config(bucket_engine);

    snprintf(topkeys_count_env, sizeof(topkeys_count_env),
             "MEMCACHED_TOP_KEYS=10");
    putenv(topkeys_count_env);

    start_memcached_server(config);
    cJSON_Delete(config);
}

void McdBucketTest::SetUp() {
    if (GetParam() == Transport::Plain) {
        current_phase = phase_plain;
        sock = connect_to_server_plain(port, false);
        ASSERT_NE(INVALID_SOCKET, sock);
    } else {
        current_phase = phase_ssl;
        sock_ssl = connect_to_server_ssl(ssl_port, false);
        ASSERT_NE(INVALID_SOCKET, sock_ssl);
    }
}

#ifdef WIN32
static void log_network_error(const char* prefix) {
    LPVOID error_msg;
    DWORD err = WSAGetLastError();

    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, 0,
                      (LPTSTR)&error_msg, 0, NULL) != 0) {
        fprintf(stderr, prefix, error_msg);
        LocalFree(error_msg);
    } else {
        fprintf(stderr, prefix, "unknown error");
    }
}
#else
static void log_network_error(const char* prefix) {
    fprintf(stderr, prefix, strerror(errno));
}
#endif

#ifdef WIN32
#define CERTIFICATE_PATH(file) ("\\tests\\cert\\"#file)
#else
#define CERTIFICATE_PATH(file) ("/tests/cert/"#file)
#endif

static void get_working_current_directory(char* out_buf, int out_buf_len) {
    bool ok = false;
#ifdef WIN32
    ok = GetCurrentDirectory(out_buf_len, out_buf) != 0;
#else
    ok = getcwd(out_buf, out_buf_len) != NULL;
#endif
    /* memcached may throw a warning, but let's push through */
    if (!ok) {
        fprintf(stderr, "Failed to determine current working directory");
        strncpy(out_buf, ".", out_buf_len);
    }
}

cJSON* McdTestappTest::generate_config(Engine_Type engine_type,
                                       int num_threads)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *array = cJSON_CreateArray();
    cJSON *obj = cJSON_CreateObject();
    cJSON *obj_ssl = NULL;
    char pem_path[256];
    char cert_path[256];
    char rbac_path[256];

    get_working_current_directory(pem_path, 256);
    strncpy(cert_path, pem_path, 256);
    snprintf(rbac_path, sizeof(rbac_path), "%s/%s", pem_path, rbac_file);
    strncat(pem_path, CERTIFICATE_PATH(testapp.pem), 256);
    strncat(cert_path, CERTIFICATE_PATH(testapp.cert), 256);

    switch(engine_type){
        case bucket_engine:
            cJSON_AddStringToObject(obj, "module", BUCKET_ENGINE);
            cJSON_AddStringToObject(obj, "config", "auto_create=false");
            break;
        case blocker_engine:
            cJSON_AddStringToObject(obj, "module", BLOCK_ENGINE);
            cJSON_AddStringToObject(obj, "config", DEFAULT_ENGINE);
            break;
        default:
            fprintf(stderr, "Incompatible engine type for Memcached config");
            break;
    }

    cJSON_AddItemReferenceToObject(root, "engine", obj);

    if (memcached_verbose) {
        cJSON_AddNumberToObject(root, "verbosity", 2);
    } else {
        obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "module", "blackhole_logger.so");
        cJSON_AddItemToArray(array, obj);
    }

    obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "module", "testapp_extension.so");
    cJSON_AddItemToArray(array, obj);

    cJSON_AddItemToObject(root, "extensions", array);

    array = cJSON_CreateArray();
    obj = cJSON_CreateObject();

    cJSON_AddNumberToObject(obj, "port", 0);

    cJSON_AddNumberToObject(obj, "maxconn", MAX_CONNECTIONS);
    cJSON_AddNumberToObject(obj, "backlog", BACKLOG);
    cJSON_AddStringToObject(obj, "host", "*");
    cJSON_AddItemToArray(array, obj);

    // We need to ensure that if >1 instance of this testsuite is run
    // at once then there each has a unique SSL port.  For the first
    // interface this is simple: we can specify the magic value '0'
    // which will cause memcached to automatically select an available
    // port, however for the second (SSL) port this isn't possible
    // (port numbers - even when zero - are used to uniquely identify
    // interfaces in memcached.  The (somewhat hacky) solution we use
    // here is to derive a SSL port number using the process ID. While
    // not guaranteed to be unique (port namespace is 16bit whereas
    // PIDs are normally at least 32bit) but given the common case
    // will be 2 testapp processes it should suffice in reality.
    uint16_t ssl_port = 40000 + (getpid() % 10000);

    obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "port", ssl_port);
    cJSON_AddNumberToObject(obj, "maxconn", MAX_CONNECTIONS);
    cJSON_AddNumberToObject(obj, "backlog", BACKLOG);
    cJSON_AddStringToObject(obj, "host", "*");
    obj_ssl = cJSON_CreateObject();
    cJSON_AddStringToObject(obj_ssl, "key", pem_path);
    cJSON_AddStringToObject(obj_ssl, "cert", cert_path);
    cJSON_AddItemToObject(obj, "ssl", obj_ssl);
    cJSON_AddItemToArray(array, obj);

    cJSON_AddItemToObject(root, "interfaces", array);

    cJSON_AddStringToObject(root, "admin", "");
    cJSON_AddTrueToObject(root, "datatype_support");
    cJSON_AddStringToObject(root, "rbac_file", rbac_path);
    if (num_threads != -1) {
        cJSON_AddNumberToObject(root, "threads", num_threads);
    }

    return root;
}

static cJSON *generate_rbac_config(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *prof;
    cJSON *obj;
    cJSON *array;
    cJSON *array2;

    /* profiles */
    array = cJSON_CreateArray();

    prof = cJSON_CreateObject();
    cJSON_AddStringToObject(prof, "name", "system");
    cJSON_AddStringToObject(prof, "description", "system internal");
    obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "allow", "all");
    cJSON_AddItemToObject(prof, "memcached", obj);
    cJSON_AddItemToArray(array, prof);

    prof = cJSON_CreateObject();
    cJSON_AddStringToObject(prof, "name", "statistics");
    cJSON_AddStringToObject(prof, "description", "only stat and assume");
    obj = cJSON_CreateObject();

    array2 = cJSON_CreateArray();
    cJSON_AddItemToArray(array2, cJSON_CreateString("stat"));
    cJSON_AddItemToArray(array2, cJSON_CreateString("assume_role"));
    cJSON_AddItemToObject(obj, "allow", array2);
    cJSON_AddItemToObject(prof, "memcached", obj);
    cJSON_AddItemToArray(array, prof);

    cJSON_AddItemToObject(root, "profiles", array);

    /* roles */
    array = cJSON_CreateArray();
    prof = cJSON_CreateObject();
    cJSON_AddStringToObject(prof, "name", "statistics");
    cJSON_AddStringToObject(prof, "profiles", "statistics");

    cJSON_AddItemToArray(array, prof);
    cJSON_AddItemToObject(root, "roles", array);

    /* users */
    array = cJSON_CreateArray();
    prof = cJSON_CreateObject();
    cJSON_AddStringToObject(prof, "login", "*");
    cJSON_AddStringToObject(prof, "profiles", "system");
    cJSON_AddStringToObject(prof, "roles", "statistics");

    cJSON_AddItemToArray(array, prof);
    cJSON_AddItemToObject(root, "users", array);

    return root;
}

static int write_config_to_file(const char* config, const char *fname) {
    FILE *fp;
    if ((fp = fopen(fname, "w")) == NULL) {
        return -1;
    } else {
        fprintf(fp, "%s", config);
        fclose(fp);
    }

    return 0;
}

static bool isMemcachedAlive() {
#ifdef WIN32
    DWORD status;
    if (GetExitCodeProcess(server_pid, &status)) {
        if (status != STILL_ACTIVE) {
            return false;
        }
    }
    // GetExitCodeProcessed failed for some reason...
    return true;
#else
    return waitpid(server_pid, 0, WNOHANG) == 0;
#endif
}

/**
 * Function to start the server and let it listen on a random port.
 * Set <code>server_pid</code> to the pid of the process
 *
 * @param port_out where to store the TCP port number the server is
 *                 listening on
 * @param daemon set to true if you want to run the memcached server
 *               as a daemon process
 */
static void start_server(in_port_t *port_out, in_port_t *ssl_port_out,
                         bool daemon, int timeout)
{
    char *filename= mcd_port_filename_env + strlen("MEMCACHED_PORT_FILENAME=");
#ifdef __sun
    char coreadm[128];
#endif
    FILE *fp;
    char buffer[80];

    snprintf(mcd_parent_monitor_env, sizeof(mcd_parent_monitor_env),
             "MEMCACHED_PARENT_MONITOR=%lu", (unsigned long)getpid());
    putenv(mcd_parent_monitor_env);

    snprintf(mcd_port_filename_env, sizeof(mcd_port_filename_env),
             "MEMCACHED_PORT_FILENAME=memcached_ports.%lu", (long)getpid());
    remove(filename);

#ifdef __sun
    /* I want to name the corefiles differently so that they don't
       overwrite each other
    */
    snprintf(coreadm, sizeof(coreadm),
             "coreadm -p core.%%f.%%p %lu", (unsigned long)getpid());
    system(coreadm);
#endif

#ifdef WIN32
    STARTUPINFO sinfo;
    PROCESS_INFORMATION pinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    memset(&pinfo, 0, sizeof(pinfo));
    sinfo.cb = sizeof(sinfo);

    char commandline[1024];
    sprintf(commandline, "memcached.exe -C %s", config_file);

    putenv(mcd_port_filename_env);

    if (!CreateProcess("memcached.exe", commandline,
                       NULL, NULL, FALSE,
                       CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                       NULL, NULL, &sinfo, &pinfo)) {
        LPVOID error_msg;
        DWORD err = GetLastError();

        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                          FORMAT_MESSAGE_FROM_SYSTEM |
                          FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, err, 0,
                          (LPTSTR)&error_msg, 0, NULL) != 0) {
            fprintf(stderr, "Failed to start process: %s\n", error_msg);
            LocalFree(error_msg);
        } else {
            fprintf(stderr, "Failed to start process: unknown error\n");
        }
        exit(EXIT_FAILURE);
    }

    server_pid = pinfo.hProcess;
#else
    server_pid = fork();
    ASSERT_NE(reinterpret_cast<pid_t>(-1), server_pid);

    if (server_pid == 0) {
        /* Child */
        const char *argv[20];
        int arg = 0;
        char tmo[24];

        snprintf(tmo, sizeof(tmo), "%u", timeout);
        putenv(mcd_port_filename_env);

        if (getenv("RUN_UNDER_VALGRIND") != NULL) {
            argv[arg++] = "valgrind";
            argv[arg++] = "--log-file=valgrind.%p.log";
            argv[arg++] = "--leak-check=full";
    #if defined(__APPLE__)
            /* Needed to ensure debugging symbols are up-to-date. */
            argv[arg++] = "--dsymutil=yes";
    #endif
        }
        argv[arg++] = "./memcached";
        argv[arg++] = "-C";
        argv[arg++] = (char*)config_file;

        argv[arg++] = NULL;
        cb_assert(execvp(argv[0], const_cast<char **>(argv)) != -1);
    }
#endif // !WIN32

    /* Yeah just let us "busy-wait" for the file to be created ;-) */
    while (access(filename, F_OK) == -1) {
        usleep(10);
        ASSERT_TRUE(isMemcachedAlive());
    }

    fp = fopen(filename, "r");
    ASSERT_NE(nullptr, fp);

    *port_out = (in_port_t)-1;
    *ssl_port_out = (in_port_t)-1;

    while ((fgets(buffer, sizeof(buffer), fp)) != NULL) {
        if (strncmp(buffer, "TCP INET: ", 10) == 0) {
            int32_t val;
            cb_assert(safe_strtol(buffer + 10, &val));
            if (*port_out == (in_port_t)-1) {
                *port_out = (in_port_t)val;
            } else {
                *ssl_port_out = (in_port_t)val;
            }
        }
    }
    fclose(fp);
    EXPECT_EQ(0, remove(filename));
}

static struct addrinfo *lookuphost(const char *hostname, in_port_t port)
{
    struct addrinfo *ai = 0;
    struct addrinfo hints;
    char service[NI_MAXSERV];
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    (void)snprintf(service, NI_MAXSERV, "%d", port);
    if ((error = getaddrinfo(hostname, service, &hints, &ai)) != 0) {
#ifdef WIN32
        log_network_error("getaddrinfo(): %s\r\n");
#else
       if (error != EAI_SYSTEM) {
          fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
       } else {
          perror("getaddrinfo()");
       }
#endif
    }

    return ai;
}



static SOCKET create_connect_plain_socket(const char *hostname, in_port_t port, bool nonblock)
{
    struct addrinfo *ai = lookuphost(hostname, port);
    SOCKET sock = INVALID_SOCKET;
    if (ai != NULL) {
       if ((sock = socket(ai->ai_family, ai->ai_socktype,
                          ai->ai_protocol)) != INVALID_SOCKET) {
          if (connect(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == SOCKET_ERROR) {
             log_network_error("Failed to connect socket: %s\n");
             closesocket(sock);
             sock = INVALID_SOCKET;
          }
       } else {
          fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
       }

       freeaddrinfo(ai);
    }
    return sock;
}

static SOCKET create_connect_ssl_socket(const char *hostname, in_port_t port, bool nonblocking) {
    char port_str[32];
    int sfd = 0;
    BIO* temp_bio = NULL;

    snprintf(port_str, 32, "%d", port);
    EXPECT_EQ(0, create_ssl_connection(&ssl_ctx, &temp_bio, hostname, port_str, NULL, NULL, 1));

    if (ssl_bio_r) {
        BIO_free(ssl_bio_r);
        ssl_bio_r = NULL;
    }
    if (ssl_bio_w) {
        BIO_free(ssl_bio_w);
        ssl_bio_w = NULL;
    }

    /* SSL "trickery". To ensure we have full control over send/receive of data.
       create_ssl_connection will have negotiated the SSL connection, now:
       1. steal the underlying FD
       2. Switch out the BIO_ssl_connect BIO for a plain memory BIO

       Now send/receive is done under our control. byte by byte, large chunks etc...
    */
    sfd = BIO_get_fd(temp_bio, NULL);
    BIO_get_ssl(temp_bio, &ssl);
    ssl_bio_r = BIO_new(BIO_s_mem());
    ssl_bio_w = BIO_new(BIO_s_mem());

    // Note: previous BIO (temp_bio) freed as a result of this call.
    SSL_set_bio(ssl, ssl_bio_r, ssl_bio_w);

    return sfd;
}

static void destroy_ssl_socket() {
    BIO_free(ssl_bio_r);
    ssl_bio_r = NULL;

    BIO_free(ssl_bio_w);
    ssl_bio_w = NULL;

    SSL_CTX_free(ssl_ctx);
}

SOCKET connect_to_server_plain(in_port_t port, bool nonblocking) {
    SOCKET sock = create_connect_plain_socket("127.0.0.1", port, nonblocking);
    if (sock == INVALID_SOCKET) {
        ADD_FAILURE() << "Failed to connect socket to port" << port;
        return INVALID_SOCKET;
    }

    if (nonblocking) {
        if (evutil_make_socket_nonblocking(sock) == -1) {
            fprintf(stderr, "evutil_make_socket_nonblocking failed\n");
            abort();
        }
    }
    return sock;
}

static SOCKET connect_to_server_ssl(in_port_t ssl_port, bool nonblocking) {
    SOCKET sock = create_connect_ssl_socket("127.0.0.1", ssl_port, nonblocking);
    if (sock == INVALID_SOCKET) {
        ADD_FAILURE() << "Failed to connect SSL socket to port" << ssl_port;
        return INVALID_SOCKET;
    }

    if (nonblocking) {
        if (evutil_make_socket_nonblocking(sock) == -1) {
            fprintf(stderr, "evutil_make_socket_nonblocking failed\n");
            abort();
        }
    }
    return sock;
}

/*
    re-connect to server.
    Uses global port and ssl_port values.
    New socket-fd written to global "sock" and "ssl_bio"
*/
static void reconnect_to_server(bool nonblocking) {
    if (current_phase == phase_ssl) {
        closesocket(sock_ssl);
        SSL_CTX_free(ssl_ctx);

        sock_ssl = connect_to_server_ssl(ssl_port, nonblocking);
        ASSERT_NE(INVALID_SOCKET, sock_ssl);
    } else {
        closesocket(sock);
        sock = connect_to_server_plain(port, nonblocking);
        ASSERT_NE(INVALID_SOCKET, sock);
    }

    ASSERT_EQ(PROTOCOL_BINARY_RESPONSE_SUCCESS, McdTestappTest::sasl_auth("mybucket",
                                                                          "mybucketpassword"));
}

static char *isasl_file;

void McdTestappTest::start_memcached_server(cJSON* config) {

    strncpy(config_file, CFG_FILE_PATTERN, sizeof(config_file));
    ASSERT_NE(cb_mktemp(config_file), nullptr);

    config_string = cJSON_Print(config);
    ASSERT_EQ(0, write_config_to_file(config_string, config_file));

    char fname[1024];
    snprintf(fname, sizeof(fname), "isasl.%lu.%lu.pw",
             (unsigned long)getpid(),
             (unsigned long)time(NULL));
    isasl_file = strdup(fname);
    ASSERT_NE(nullptr, isasl_file);

    FILE *fp = fopen(isasl_file, "w");
    ASSERT_NE(nullptr, fp);
    fprintf(fp, "_admin password \n");
    fprintf(fp, "mybucket mybucketpassword \n");
    fclose(fp);

    snprintf(isasl_pwfile_env, sizeof(isasl_pwfile_env), "ISASL_PWFILE=%s",
             isasl_file);
    putenv(isasl_pwfile_env);

    // We need to set MEMCACHED_UNIT_TESTS to enable the use of
    // the ewouldblock engine..
    static char envvar[80];
    snprintf(envvar, sizeof(envvar), "MEMCACHED_UNIT_TESTS=true");
    putenv(envvar);

    server_start_time = time(0);
    start_server(&port, &ssl_port, false, 600);
}

static void stop_memcached_server(void) {
    closesocket(sock);
    sock = INVALID_SOCKET;

    if (server_pid != reinterpret_cast<pid_t>(-1)) {
#ifdef WIN32
        TerminateProcess(server_pid, 0);
#else
        if (kill(server_pid, SIGTERM) == 0) {
            /* Wait for the process to be gone... */
            waitpid(server_pid, NULL, 0);
        }
#endif
    }

    cJSON_Free(config_string);
    EXPECT_NE(-1, remove(config_file));
    EXPECT_NE(-1, remove(isasl_file));
    free(isasl_file);
}

static ssize_t socket_send(SOCKET s, const char *buf, size_t len)
{
#ifdef WIN32
    return send(s, buf, (int)len, 0);
#else
    return send(s, buf, len, 0);
#endif
}

static ssize_t phase_send(const void *buf, size_t len) {
    ssize_t rv = 0, send_rv = 0;
    if (current_phase == phase_ssl) {
        long send_len = 0;
        char *send_buf = NULL;
        /* push the data through SSL into the BIO */
        rv = (ssize_t)SSL_write(ssl, (const char*)buf, (int)len);
        send_len = BIO_get_mem_data(ssl_bio_w, &send_buf);

        send_rv = socket_send(sock_ssl, send_buf, send_len);

        if (send_rv > 0) {
            EXPECT_EQ(send_len, send_rv);
            (void)BIO_reset(ssl_bio_w);
        } else {
            /* flag failure to user */
            rv = send_rv;
        }
    } else {
        rv = socket_send(sock, reinterpret_cast<const char*>(buf), len);
    }
    return rv;
}

static ssize_t socket_recv(SOCKET s, char *buf, size_t len)
{
#ifdef WIN32
    return recv(s, buf, (int)len, 0);
#else
    return recv(s, buf, len, 0);
#endif
}

static ssize_t phase_recv(void *buf, size_t len) {

    ssize_t rv = 0;
    if (current_phase == phase_ssl) {
        /* can we read some data? */
        while((rv = SSL_peek(ssl, buf, (int)len)) == -1)
        {
            /* nope, keep feeding SSL until we can */
            rv = socket_recv(sock_ssl, reinterpret_cast<char*>(buf), len);

            if(rv > 0) {
                /* write into the BIO what came off the network */
                BIO_write(ssl_bio_r, buf, rv);
            } else if(rv == 0) {
                return rv; /* peer closed */
            }
        }
        /* now pull the data out and return */
        rv = SSL_read(ssl, buf, (int)len);
    } else {
        rv = socket_recv(sock, reinterpret_cast<char*>(buf), len);
    }
    return rv;
}

char ssl_error_string[256];
int ssl_error_string_len = 256;

static char* phase_get_errno() {
    char * rv = 0;
    if (current_phase == phase_ssl) {
        /* could do with more work here, but so far this has sufficed */
        snprintf(ssl_error_string, ssl_error_string_len, "SSL error\n");
        rv = ssl_error_string;
    } else {
        rv = strerror(errno);
    }
    return rv;
}

void safe_send(const void* buf, size_t len, bool hickup)
{
    size_t offset = 0;
    const char* ptr = reinterpret_cast<const char*>(buf);
    do {
        size_t num_bytes = len - offset;
        ssize_t nw;
        if (hickup) {
            if (num_bytes > 1024) {
                num_bytes = (rand() % 1023) + 1;
            }
        }

        nw = phase_send(ptr + offset, num_bytes);

        if (nw == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to write: %s\n", phase_get_errno());
                abort();
            }
        } else {
            if (hickup) {
#ifndef WIN32
                usleep(100);
#endif
            }
            offset += nw;
        }
    } while (offset < len);
}

static bool safe_recv(void *buf, size_t len) {
    size_t offset = 0;
    if (len == 0) {
        return true;
    }
    do {

        ssize_t nr = phase_recv(((char*)buf) + offset, len - offset);

        if (nr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to read: %s\n", phase_get_errno());
                abort();
            }
        } else {
            if (nr == 0 && allow_closed_read) {
                return false;
            }
            cb_assert(nr != 0);
            offset += nr;
        }
    } while (offset < len);

    return true;
}

bool safe_recv_packet(void *buf, size_t size) {
    protocol_binary_response_no_extras *response =
            reinterpret_cast<protocol_binary_response_no_extras*>(buf);
    size_t len;

    cb_assert(size >= sizeof(*response));
    if (!safe_recv(response, sizeof(*response))) {
        return false;
    }
    response->message.header.response.keylen = ntohs(response->message.header.response.keylen);
    response->message.header.response.status = ntohs(response->message.header.response.status);
    response->message.header.response.bodylen = ntohl(response->message.header.response.bodylen);

    len = sizeof(*response);
    char* ptr = reinterpret_cast<char*>(buf);
    ptr += len;
    cb_assert(size >= (sizeof(*response) + response->message.header.response.bodylen));
    if (!safe_recv(ptr, response->message.header.response.bodylen)) {
        return false;
    }

    return true;
}

/** Constructs a storage command using the give arguments into buf. Returns
 *  the number of bytes written.
 */
static size_t storage_command(char*buf,
                             size_t bufsz,
                             uint8_t cmd,
                             const void* key,
                             size_t keylen,
                             const void* dta,
                             size_t dtalen,
                             uint32_t flags,
                             uint32_t exp) {
    /* all of the storage commands use the same command layout */
    size_t key_offset;
    protocol_binary_request_set *request =
        reinterpret_cast<protocol_binary_request_set*>(buf);
    cb_assert(bufsz >= sizeof(*request) + keylen + dtalen);

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;
    request->message.header.request.keylen = htons((uint16_t)keylen);
    request->message.header.request.extlen = 8;
    request->message.header.request.bodylen = htonl((uint32_t)(keylen + 8 + dtalen));
    request->message.header.request.opaque = 0xdeadbeef;
    request->message.body.flags = htonl(flags);
    request->message.body.expiration = htonl(exp);

    key_offset = sizeof(protocol_binary_request_no_extras) + 8;

    memcpy(buf + key_offset, key, keylen);
    if (dta != NULL) {
        memcpy(buf + key_offset + keylen, dta, dtalen);
    }

    return key_offset + keylen + dtalen;
}

off_t raw_command(char* buf,
                         size_t bufsz,
                         uint8_t cmd,
                         const void* key,
                         size_t keylen,
                         const void* dta,
                         size_t dtalen) {
    /* all of the storage commands use the same command layout */
    off_t key_offset;
    protocol_binary_request_no_extras *request =
        reinterpret_cast<protocol_binary_request_no_extras*>(buf);
    EXPECT_GE(bufsz, (sizeof(*request) + keylen + dtalen));

    memset(request, 0, sizeof(*request));
    if (cmd == read_command || cmd == write_command) {
        request->message.header.request.extlen = 8;
    } else if (cmd == PROTOCOL_BINARY_CMD_AUDIT_PUT) {
        request->message.header.request.extlen = 4;
    } else if (cmd == PROTOCOL_BINARY_CMD_EWOULDBLOCK_CTL) {
        request->message.header.request.extlen = 12;
    }
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;
    request->message.header.request.keylen = htons((uint16_t)keylen);
    request->message.header.request.bodylen = htonl((uint32_t)(keylen + dtalen + request->message.header.request.extlen));
    request->message.header.request.opaque = 0xdeadbeef;

    key_offset = sizeof(protocol_binary_request_no_extras) +
        request->message.header.request.extlen;

    if (key != NULL) {
        memcpy(buf + key_offset, key, keylen);
    }
    if (dta != NULL) {
        memcpy(buf + key_offset + keylen, dta, dtalen);
    }

    return (off_t)(sizeof(*request) + keylen + dtalen + request->message.header.request.extlen);
}

static off_t flush_command(char* buf, size_t bufsz, uint8_t cmd, uint32_t exptime, bool use_extra) {
    off_t size;
    protocol_binary_request_flush *request =
        reinterpret_cast<protocol_binary_request_flush*>(buf);
    cb_assert(bufsz > sizeof(*request));

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;

    size = sizeof(protocol_binary_request_no_extras);
    if (use_extra) {
        request->message.header.request.extlen = 4;
        request->message.body.expiration = htonl(exptime);
        request->message.header.request.bodylen = htonl(4);
        size += 4;
    }

    request->message.header.request.opaque = 0xdeadbeef;

    return size;
}

static off_t arithmetic_command(char* buf,
                                size_t bufsz,
                                uint8_t cmd,
                                const void* key,
                                size_t keylen,
                                uint64_t delta,
                                uint64_t initial,
                                uint32_t exp) {
    off_t key_offset;
    protocol_binary_request_incr *request =
            reinterpret_cast<protocol_binary_request_incr*>(buf);
    cb_assert(bufsz > sizeof(*request) + keylen);

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;
    request->message.header.request.keylen = htons((uint16_t)keylen);
    request->message.header.request.extlen = 20;
    request->message.header.request.bodylen = htonl((uint32_t)(keylen + 20));
    request->message.header.request.opaque = 0xdeadbeef;
    request->message.body.delta = htonll(delta);
    request->message.body.initial = htonll(initial);
    request->message.body.expiration = htonl(exp);

    key_offset = sizeof(protocol_binary_request_no_extras) + 20;

    memcpy(buf + key_offset, key, keylen);
    return (off_t)(key_offset + keylen);
}

void validate_response_header(protocol_binary_response_no_extras *response,
                              uint8_t cmd, uint16_t status)
{
    protocol_binary_response_header* header = &response->message.header;

    EXPECT_EQ(PROTOCOL_BINARY_RES, header->response.magic);
    EXPECT_EQ(cmd, header->response.opcode)
        << "Expected (as string): '" << memcached_opcode_2_text(cmd)
        << "', actual (as string): '"
        << memcached_opcode_2_text((header->response.opcode)) << "'";

    EXPECT_EQ(PROTOCOL_BINARY_RAW_BYTES, header->response.datatype);
    if (status == PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND) {
        if (header->response.status == PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED) {
            header->response.status = PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND;
        }
    }
    EXPECT_EQ(status, header->response.status)
        << "Expected (as string): '"
        << memcached_protocol_errcode_2_text(static_cast<protocol_binary_response_status>(status))
        << "', actual (as string): '"
        << memcached_protocol_errcode_2_text(static_cast<protocol_binary_response_status>(header->response.status))
        << "'";

    EXPECT_EQ(0xdeadbeef, header->response.opaque);

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        switch (cmd) {
        case PROTOCOL_BINARY_CMD_ADDQ:
        case PROTOCOL_BINARY_CMD_APPENDQ:
        case PROTOCOL_BINARY_CMD_DECREMENTQ:
        case PROTOCOL_BINARY_CMD_DELETEQ:
        case PROTOCOL_BINARY_CMD_FLUSHQ:
        case PROTOCOL_BINARY_CMD_INCREMENTQ:
        case PROTOCOL_BINARY_CMD_PREPENDQ:
        case PROTOCOL_BINARY_CMD_QUITQ:
        case PROTOCOL_BINARY_CMD_REPLACEQ:
        case PROTOCOL_BINARY_CMD_SETQ:
            ADD_FAILURE() << "Quiet command shouldn't return on success";
        default:
            break;
        }

        switch (cmd) {
        case PROTOCOL_BINARY_CMD_ADD:
        case PROTOCOL_BINARY_CMD_REPLACE:
        case PROTOCOL_BINARY_CMD_SET:
        case PROTOCOL_BINARY_CMD_APPEND:
        case PROTOCOL_BINARY_CMD_PREPEND:
            EXPECT_EQ(0, header->response.keylen);
            /* extlen/bodylen are permitted to be either zero, or 16 if
             * MUTATION_SEQNO is enabled.
             */
            EXPECT_TRUE(header->response.extlen == 0 ||
                        header->response.extlen == 16);
            EXPECT_TRUE(header->response.bodylen == 0 ||
                        header->response.bodylen == 16);
            EXPECT_NE(header->response.cas, 0u);
            break;
        case PROTOCOL_BINARY_CMD_FLUSH:
        case PROTOCOL_BINARY_CMD_NOOP:
        case PROTOCOL_BINARY_CMD_QUIT:
            EXPECT_EQ(0, header->response.keylen);
            EXPECT_EQ(0, header->response.extlen);
            EXPECT_EQ(0u, header->response.bodylen);
            break;
        case PROTOCOL_BINARY_CMD_DELETE:
            EXPECT_EQ(0, header->response.keylen);
            /* extlen/bodylen are permitted to be either zero, or 16 if
             * MUTATION_SEQNO is enabled.
             */
            EXPECT_TRUE(header->response.extlen == 0 ||
                        header->response.extlen == 16);
            EXPECT_TRUE(header->response.bodylen == 0 ||
                        header->response.bodylen == 16);
            break;
        case PROTOCOL_BINARY_CMD_DECREMENT:
        case PROTOCOL_BINARY_CMD_INCREMENT:
            EXPECT_EQ(0, header->response.keylen);
            /* extlen is permitted to be either zero, or 16 if MUTATION_SEQNO
             * is enabled.
             */
            EXPECT_TRUE(header->response.extlen == 0 ||
                        header->response.extlen == 16);
            /* similary, bodylen must be either 8 or 24. */
            EXPECT_TRUE(header->response.bodylen == 8 ||
                        header->response.bodylen == 24);
            EXPECT_NE(0u, header->response.cas);
            break;

        case PROTOCOL_BINARY_CMD_STAT:
            EXPECT_EQ(0, header->response.extlen);
            /* key and value exists in all packets except in the terminating */
            EXPECT_EQ(0u, header->response.cas);
            break;

        case PROTOCOL_BINARY_CMD_VERSION:
            EXPECT_EQ(0, header->response.keylen);
            EXPECT_EQ(0, header->response.extlen);
            EXPECT_NE(0u, header->response.bodylen);
            EXPECT_EQ(0u, header->response.cas);
            break;

        case PROTOCOL_BINARY_CMD_GET:
        case PROTOCOL_BINARY_CMD_GETQ:
            EXPECT_EQ(0, header->response.keylen);
            EXPECT_EQ(4, header->response.extlen);
            EXPECT_NE(0u, header->response.cas);
            break;

        case PROTOCOL_BINARY_CMD_GETK:
        case PROTOCOL_BINARY_CMD_GETKQ:
            EXPECT_NE(0, header->response.keylen);
            EXPECT_EQ(4, header->response.extlen);
            EXPECT_NE(0u, header->response.cas);
            break;
        case PROTOCOL_BINARY_CMD_SUBDOC_GET:
            EXPECT_EQ(0, header->response.keylen);
            EXPECT_EQ(0, header->response.extlen);
            EXPECT_NE(0u, header->response.bodylen);
            EXPECT_NE(0u, header->response.cas);
            break;
        case PROTOCOL_BINARY_CMD_SUBDOC_EXISTS:
            EXPECT_EQ(0, header->response.keylen);
            EXPECT_EQ(0, header->response.extlen);
            EXPECT_EQ(0u, header->response.bodylen);
            EXPECT_NE(0u, header->response.cas);
            break;
        case PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD:
        case PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT:
            EXPECT_EQ(0, header->response.keylen);
            EXPECT_EQ(0, header->response.extlen);
            EXPECT_EQ(0u, header->response.bodylen);
            EXPECT_NE(0u, header->response.cas);
            break;
        default:
            /* Undefined command code */
            break;
        }
    } else {
        EXPECT_EQ(0u, header->response.cas);
        EXPECT_EQ(0, header->response.extlen);
        if (cmd != PROTOCOL_BINARY_CMD_GETK) {
            EXPECT_EQ(0, header->response.keylen);
        }
    }
}

static void validate_arithmetic(const protocol_binary_response_incr* incr,
                          uint64_t expected) {
    const uint8_t *ptr = incr->bytes
            + sizeof(incr->message.header)
            + incr->message.header.response.extlen;
    const uint64_t result = ntohll(*(uint64_t*)ptr);
    EXPECT_EQ(expected, result);

    /* Check for extras - if present should be {vbucket_uuid, seqno) pair for
     * mutation seqno support. */
    if (incr->message.header.response.extlen != 0) {
        EXPECT_EQ(16, incr->message.header.response.extlen);
    }
}


// Configues the ewouldblock_engine to use the given mode; value
// is a mode-specific parameter.
void McdTestappTest::ewouldblock_engine_configure(ENGINE_ERROR_CODE err_code,
                                                  EWBEngine_Mode mode,
                                                  uint32_t value) {
    union {
        request_ewouldblock_ctl request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_EWOULDBLOCK_CTL,
                             NULL, 0, NULL, 0);
    buffer.request.message.body.mode = htonl(mode);
    buffer.request.message.body.value = htonl(value);
    buffer.request.message.body.inject_error = htonl(err_code);

    safe_send(buffer.bytes, len, false);

    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_EWOULDBLOCK_CTL,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

void McdTestappTest::ewouldblock_engine_disable() {
    // Value for err_code doesn't matter...
    ewouldblock_engine_configure(ENGINE_EWOULDBLOCK, EWBEngineMode_NEXT_N, 0);
}

// Note: retained as a seperate function as other tests call this.
void test_noop(void) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_NOOP,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_NOOP,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, Noop) {
    test_noop();
}

void test_quit_impl(uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             cmd, NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_QUIT) {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_QUIT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    /* Socket should be closed now, read should return 0 */
    EXPECT_EQ(0, phase_recv(buffer.bytes, sizeof(buffer.bytes)));

    reconnect_to_server(false);
}

TEST_P(McdTestappTest, Quit) {
    test_quit_impl(PROTOCOL_BINARY_CMD_QUIT);
}

TEST_P(McdTestappTest, QuitQ) {
    test_quit_impl(PROTOCOL_BINARY_CMD_QUITQ);
}

void test_set_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    uint64_t value = 0xdeadbeefdeadcafe;
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                                 key, strlen(key), &value, sizeof(value),
                                 0, 0);

    /* Set should work over and over again */
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_SET) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
        }
    }

    if (cmd == PROTOCOL_BINARY_CMD_SETQ) {
        return test_noop();
    }

    send.request.message.header.request.cas = receive.response.message.header.response.cas;
    safe_send(send.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_SET) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
        EXPECT_NE(receive.response.message.header.response.cas,
                  send.request.message.header.request.cas);
    } else {
        return test_noop();
    }
}

TEST_P(McdTestappTest, Set) {
    test_set_impl("test_set", PROTOCOL_BINARY_CMD_SET);
}

TEST_P(McdTestappTest, SetQ) {
    test_set_impl("test_setq", PROTOCOL_BINARY_CMD_SETQ);
}

static enum test_return test_add_impl(const char *key, uint8_t cmd) {
    uint64_t value = 0xdeadbeefdeadcafe;
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd, key,
                                 strlen(key), &value, sizeof(value),
                                 0, 0);

    /* Add should only work the first time */
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (ii == 0) {
            if (cmd == PROTOCOL_BINARY_CMD_ADD) {
                safe_recv_packet(receive.bytes, sizeof(receive.bytes));
                validate_response_header(&receive.response, cmd,
                                         PROTOCOL_BINARY_RESPONSE_SUCCESS);
            }
        } else {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);
        }
    }

    /* And verify that it doesn't work with the "correct" CAS */
    /* value */
    send.request.message.header.request.cas = receive.response.message.header.response.cas;
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);

    delete_object(key);

    return TEST_PASS;
}

TEST_P(McdTestappTest, Add) {
    test_add_impl("test_add", PROTOCOL_BINARY_CMD_ADD);
}

TEST_P(McdTestappTest, AddQ) {
    test_add_impl("test_addq", PROTOCOL_BINARY_CMD_ADDQ);
}

static enum test_return test_replace_impl(const char* key, uint8_t cmd) {
    uint64_t value = 0xdeadbeefdeadcafe;
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    int ii;
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                                 key, strlen(key), &value, sizeof(value),
                                 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), &value, sizeof(value), 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                          key, strlen(key), &value, sizeof(value), 0, 0);
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_REPLACE) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response,
                                     PROTOCOL_BINARY_CMD_REPLACE,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
        }
    }

    if (cmd == PROTOCOL_BINARY_CMD_REPLACEQ) {
        test_noop();
    }

    delete_object(key);

    return TEST_PASS;
}

TEST_P(McdTestappTest, Replace) {
    test_replace_impl("test_replace", PROTOCOL_BINARY_CMD_REPLACE);
}

TEST_P(McdTestappTest, ReplaceQ) {
    test_replace_impl("test_replaceq", PROTOCOL_BINARY_CMD_REPLACEQ);
}

static enum test_return test_delete_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                             key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), NULL, 0, 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes),
                      cmd, key, strlen(key), NULL, 0);
    safe_send(send.bytes, len, false);

    if (cmd == PROTOCOL_BINARY_CMD_DELETE) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_DELETE,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    return TEST_PASS;
}

TEST_P(McdTestappTest, Delete) {
    test_delete_impl("test_delete", PROTOCOL_BINARY_CMD_DELETE);
}

TEST_P(McdTestappTest, DeleteQ) {
    test_delete_impl("test_deleteq", PROTOCOL_BINARY_CMD_DELETEQ);
}

static enum test_return test_delete_cas_impl(const char *key, bool bad) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len;
    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_SET,
                          key, strlen(key), NULL, 0, 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
    len = raw_command(send.bytes, sizeof(send.bytes),
                       PROTOCOL_BINARY_CMD_DELETE, key, strlen(key), NULL, 0);

    send.request.message.header.request.cas = receive.response.message.header.response.cas;
    if (bad) {
        ++send.request.message.header.request.cas;
    }
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    if (bad) {
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_DELETE,
                                 PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);
    } else {
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_DELETE,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    return TEST_PASS;
}


TEST_P(McdTestappTest, DeleteCAS) {
    test_delete_cas_impl("test_delete_cas", false);
}

TEST_P(McdTestappTest, DeleteBadCAS) {
    test_delete_cas_impl("test_delete_bad_cas", true);
}

TEST_P(McdTestappTest, DeleteMutationSeqno) {
    /* Enable mutation seqno support, then call the normal delete test. */
    set_mutation_seqno_feature(true);
    test_delete_impl("test_delete_mutation_seqno", PROTOCOL_BINARY_CMD_DELETE);
    set_mutation_seqno_feature(false);
}

static enum test_return test_get_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    int ii;
    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                             key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), NULL, 0,
                          0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    /* run a little pipeline test ;-) */
    len = 0;
    for (ii = 0; ii < 10; ++ii) {
        union {
            protocol_binary_request_no_extras request;
            char bytes[1024];
        } temp;
        size_t l = raw_command(temp.bytes, sizeof(temp.bytes),
                               cmd, key, strlen(key), NULL, 0);
        memcpy(send.bytes + len, temp.bytes, l);
        len += l;
    }

    safe_send(send.bytes, len, false);
    for (ii = 0; ii < 10; ++ii) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    delete_object(key);
    return TEST_PASS;
}

TEST_P(McdTestappTest, Get) {
    test_get_impl("test_get", PROTOCOL_BINARY_CMD_GET);
}

TEST_P(McdTestappTest, GetK) {
    test_get_impl("test_getk", PROTOCOL_BINARY_CMD_GETK);
}

static enum test_return test_getq_impl(const char *key, uint8_t cmd) {
    const char *missing = "test_getq_missing";
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, temp, receive;
    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_BINARY_CMD_ADD,
                                 key, strlen(key), NULL, 0,
                                 0, 0);
    size_t len2 = raw_command(temp.bytes, sizeof(temp.bytes), cmd,
                             missing, strlen(missing), NULL, 0);
    /* I need to change the first opaque so that I can separate the two
     * return packets */
    temp.request.message.header.request.opaque = 0xfeedface;
    memcpy(send.bytes + len, temp.bytes, len2);
    len += len2;

    len2 = raw_command(temp.bytes, sizeof(temp.bytes), cmd,
                       key, strlen(key), NULL, 0);
    memcpy(send.bytes + len, temp.bytes, len2);
    len += len2;

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
    /* The first GETQ shouldn't return anything */
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    delete_object(key);
    return TEST_PASS;
}

TEST_P(McdTestappTest, GetQ) {
    EXPECT_EQ(TEST_PASS,
              test_getq_impl("test_getq", PROTOCOL_BINARY_CMD_GETQ));
}

TEST_P(McdTestappTest, GetKQ) {
    EXPECT_EQ(TEST_PASS,
              test_getq_impl("test_getkq", PROTOCOL_BINARY_CMD_GETKQ));
}

static enum test_return test_incr_impl(const char* key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response_header;
        protocol_binary_response_incr response;
        char bytes[1024];
    } send, receive;
    size_t len = arithmetic_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), 1, 0, 0);

    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_INCREMENT) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response_header, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
            validate_arithmetic(&receive.response, ii);
        }
    }

    if (cmd == PROTOCOL_BINARY_CMD_INCREMENTQ) {
        test_noop();
    }

    delete_object(key);
    return TEST_PASS;
}

TEST_P(McdTestappTest, Incr) {
    test_incr_impl("test_incr", PROTOCOL_BINARY_CMD_INCREMENT);
}

TEST_P(McdTestappTest, IncrQ) {
    test_incr_impl("test_incrq", PROTOCOL_BINARY_CMD_INCREMENTQ);
}

static enum test_return test_incr_invalid_cas_impl(const char* key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response_header;
        protocol_binary_response_incr response;
        char bytes[1024];
    } send, receive;
    size_t len = arithmetic_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), 1, 0, 0);

    send.request.message.header.request.cas = 5;
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response_header, cmd,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);
    return TEST_PASS;
}

TEST_P(McdTestappTest, InvalidCASIncr) {
    test_incr_invalid_cas_impl("test_incr", PROTOCOL_BINARY_CMD_INCREMENT);
}

TEST_P(McdTestappTest, InvalidCASIncrQ) {
    test_incr_invalid_cas_impl("test_incrq", PROTOCOL_BINARY_CMD_INCREMENTQ);
}

TEST_P(McdTestappTest, InvalidCASDecr) {
    test_incr_invalid_cas_impl("test_decr", PROTOCOL_BINARY_CMD_DECREMENT);
}

TEST_P(McdTestappTest, InvalidCASDecrQ) {
    test_incr_invalid_cas_impl("test_decrq", PROTOCOL_BINARY_CMD_DECREMENTQ);
}

static enum test_return test_decr_impl(const char* key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response_header;
        protocol_binary_response_decr response;
        char bytes[1024];
    } send, receive;
    size_t len = arithmetic_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), 1, 9, 0);

    int ii;
    for (ii = 9; ii >= 0; --ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_DECREMENT) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response_header, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
            validate_arithmetic(&receive.response, ii);
        }
    }

    /* decr on 0 should not wrap */
    safe_send(send.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_DECREMENT) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response_header, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
        validate_arithmetic(&receive.response, 0);
    } else {
        test_noop();
    }

    delete_object(key);
    return TEST_PASS;
}

TEST_P(McdTestappTest, Decr) {
    test_decr_impl("test_decr",PROTOCOL_BINARY_CMD_DECREMENT);
}

TEST_P(McdTestappTest, DecrQ) {
    test_decr_impl("test_decrq", PROTOCOL_BINARY_CMD_DECREMENTQ);
}

TEST_P(McdTestappTest, IncrMutationSeqno) {
    /* Enable mutation seqno support, then call the normal incr test. */
    set_mutation_seqno_feature(true);
    test_incr_impl("test_incr_mutation_seqno", PROTOCOL_BINARY_CMD_INCREMENT);
    set_mutation_seqno_feature(false);
}

TEST_P(McdTestappTest, DecrMutationSeqno) {
    /* Enable mutation seqno support, then call the normal decr test. */
    set_mutation_seqno_feature(true);
    test_decr_impl("test_decr_mutation_seqno", PROTOCOL_BINARY_CMD_DECREMENT);
    set_mutation_seqno_feature(false);
}

TEST_P(McdTestappTest, Version) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_VERSION,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_VERSION,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

static enum test_return test_flush_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    int ii;

    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_BINARY_CMD_ADD,
                                 key, strlen(key), NULL, 0, 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = flush_command(send.bytes, sizeof(send.bytes), cmd, 2, true);
    safe_send(send.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_FLUSH) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_GET,
                      key, strlen(key), NULL, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

#ifdef WIN32
    Sleep(2000);
#else
    sleep(2);
#endif
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    for (ii = 0; ii < 2; ++ii) {
        len = storage_command(send.bytes, sizeof(send.bytes),
                              PROTOCOL_BINARY_CMD_ADD,
                              key, strlen(key), NULL, 0, 0, 0);
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);

        len = flush_command(send.bytes, sizeof(send.bytes), cmd, 0, ii == 0);
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_FLUSH) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
        }

        len = raw_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_GET,
                          key, strlen(key), NULL, 0);
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                                 PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    }

    return TEST_PASS;
}

TEST_P(McdTestappTest, Flush) {
    test_flush_impl("test_flush", PROTOCOL_BINARY_CMD_FLUSH);
}

TEST_P(McdTestappTest, FlushQ) {
    test_flush_impl("test_flushq", PROTOCOL_BINARY_CMD_FLUSHQ);
}

TEST_P(McdTestappTest, CAS) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    uint64_t value = 0xdeadbeefdeadcafe;
    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_BINARY_CMD_SET,
                                 "FOO", 3, &value, sizeof(value), 0, 0);

    send.request.message.header.request.cas = 0x7ffffff;
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    send.request.message.header.request.cas = 0x0;
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    send.request.message.header.request.cas = receive.response.message.header.response.cas;
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    send.request.message.header.request.cas = receive.response.message.header.response.cas - 1;
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);

    // Cleanup
    delete_object("FOO");
}

void test_concat_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    const char *value = "world";
    char *ptr;
    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                              key, strlen(key), value, strlen(value));


    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_NOT_STORED);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), value, strlen(value), 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                      key, strlen(key), value, strlen(value));
    safe_send(send.bytes, len, false);

    if (cmd == PROTOCOL_BINARY_CMD_APPEND || cmd == PROTOCOL_BINARY_CMD_PREPEND) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    } else {
        len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_NOOP,
                          NULL, 0, NULL, 0);
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_NOOP,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_GETK,
                      key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GETK,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    EXPECT_EQ(strlen(key), receive.response.message.header.response.keylen);
    EXPECT_EQ((strlen(key) + 2*strlen(value) + 4),
              receive.response.message.header.response.bodylen);

    ptr = receive.bytes;
    ptr += sizeof(receive.response);
    ptr += 4;

    EXPECT_EQ(0, memcmp(ptr, key, strlen(key)));
    ptr += strlen(key);
    EXPECT_EQ(0, memcmp(ptr, value, strlen(value)));
    ptr += strlen(value);
    EXPECT_EQ(0, memcmp(ptr, value, strlen(value)));

    // Cleanup
    delete_object(key);
}

TEST_P(McdTestappTest, Append) {
    test_concat_impl("test_append", PROTOCOL_BINARY_CMD_APPEND);
}

TEST_P(McdTestappTest, Prepend) {
    test_concat_impl("test_prepend", PROTOCOL_BINARY_CMD_PREPEND);
}

TEST_P(McdTestappTest, AppendQ) {
    test_concat_impl("test_appendq", PROTOCOL_BINARY_CMD_APPENDQ);
}

TEST_P(McdTestappTest, PrependQ) {
    test_concat_impl("test_prependq", PROTOCOL_BINARY_CMD_PREPENDQ);
}

TEST_P(McdTestappTest, Stat) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_STAT,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    do {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_STAT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    } while (buffer.response.message.header.response.keylen != 0);
}

TEST_P(McdTestappTest, StatConnections) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[2048];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_STAT,
                             "connections", strlen("connections"), NULL, 0);

    safe_send(buffer.bytes, len, false);
    do {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_STAT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    } while (buffer.response.message.header.response.keylen != 0);
}

TEST_P(McdTestappTest, Scrub) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, recv;

    size_t len = raw_command(send.bytes, sizeof(send.bytes),
                             PROTOCOL_BINARY_CMD_SCRUB, NULL, 0, NULL, 0);

    // Retry if scrubber is already running.
    do {
        safe_send(send.bytes, len, false);
        safe_recv_packet(recv.bytes, sizeof(recv.bytes));
    } while (recv.response.message.header.response.status == PROTOCOL_BINARY_RESPONSE_EBUSY);

    validate_response_header(&recv.response, PROTOCOL_BINARY_CMD_SCRUB,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, Roles) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_ASSUME_ROLE,
                             "unknownrole", 11, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_ASSUME_ROLE,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);


    /* assume the statistics role */
    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_ASSUME_ROLE,
                             "statistics", 10, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_ASSUME_ROLE,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    /* At this point I should get an EACCESS if I tried to run NOOP */
    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_NOOP,
                      NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_NOOP,
                             PROTOCOL_BINARY_RESPONSE_EACCESS);

    /* But I should be allowed to run a stat */
    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_STAT,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    do {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_STAT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    } while (buffer.response.message.header.response.keylen != 0);

    /* Drop the role */
    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_ASSUME_ROLE,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_ASSUME_ROLE,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    /* And noop should work again! */
    test_noop();
}

std::atomic_bool hickup_thread_running;

static void binary_hickup_recv_verification_thread(void *arg) {
    protocol_binary_response_no_extras *response =
            reinterpret_cast<protocol_binary_response_no_extras*>(malloc(65*1024));
    if (response != NULL) {
        while (safe_recv_packet(response, 65*1024)) {
            /* Just validate the packet format */
            validate_response_header(response,
                                     response->message.header.response.opcode,
                                     response->message.header.response.status);
        }
        free(response);
    }
    hickup_thread_running = false;
    allow_closed_read = false;
}

static enum test_return test_pipeline_hickup_chunk(void *buffer, size_t buffersize) {
    off_t offset = 0;
    char *key[256] = {0};
    uint64_t value = 0xfeedfacedeadbeef;

    while (hickup_thread_running &&
           offset + sizeof(protocol_binary_request_no_extras) < buffersize) {
        union {
            protocol_binary_request_no_extras request;
            char bytes[65 * 1024];
        } command;
        uint8_t cmd = (uint8_t)(rand() & 0xff);
        size_t len;
        size_t keylen = (rand() % 250) + 1;

        switch (cmd) {
        case PROTOCOL_BINARY_CMD_ADD:
        case PROTOCOL_BINARY_CMD_ADDQ:
        case PROTOCOL_BINARY_CMD_REPLACE:
        case PROTOCOL_BINARY_CMD_REPLACEQ:
        case PROTOCOL_BINARY_CMD_SET:
        case PROTOCOL_BINARY_CMD_SETQ:
            len = storage_command(command.bytes, sizeof(command.bytes), cmd,
                                  key, keylen , &value, sizeof(value),
                                  0, 0);
            break;
        case PROTOCOL_BINARY_CMD_APPEND:
        case PROTOCOL_BINARY_CMD_APPENDQ:
        case PROTOCOL_BINARY_CMD_PREPEND:
        case PROTOCOL_BINARY_CMD_PREPENDQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                              key, keylen, &value, sizeof(value));
            break;
        case PROTOCOL_BINARY_CMD_NOOP:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                              NULL, 0, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_DELETE:
        case PROTOCOL_BINARY_CMD_DELETEQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                             key, keylen, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_DECREMENT:
        case PROTOCOL_BINARY_CMD_DECREMENTQ:
        case PROTOCOL_BINARY_CMD_INCREMENT:
        case PROTOCOL_BINARY_CMD_INCREMENTQ:
            len = arithmetic_command(command.bytes, sizeof(command.bytes), cmd,
                                     key, keylen, 1, 0, 0);
            break;
        case PROTOCOL_BINARY_CMD_VERSION:
            len = raw_command(command.bytes, sizeof(command.bytes),
                             PROTOCOL_BINARY_CMD_VERSION,
                             NULL, 0, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_GET:
        case PROTOCOL_BINARY_CMD_GETK:
        case PROTOCOL_BINARY_CMD_GETKQ:
        case PROTOCOL_BINARY_CMD_GETQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                             key, keylen, NULL, 0);
            break;

        case PROTOCOL_BINARY_CMD_STAT:
            len = raw_command(command.bytes, sizeof(command.bytes),
                              PROTOCOL_BINARY_CMD_STAT,
                              NULL, 0, NULL, 0);
            break;

        default:
            /* don't run commands we don't know */
            continue;
        }

        if ((len + offset) < buffersize) {
            memcpy(((char*)buffer) + offset, command.bytes, len);
            offset += (off_t)len;
        } else {
            break;
        }
    }
    safe_send(buffer, offset, true);

    return TEST_PASS;
}

TEST_P(McdTestappTest, PipelineHickup)
{
    std::vector<char> buffer(65 * 1024);
    int ii;
    cb_thread_t tid;
    int ret;
    size_t len;

    allow_closed_read = true;
    hickup_thread_running = true;
    if ((ret = cb_create_thread(&tid, binary_hickup_recv_verification_thread,
                                NULL, 0)) != 0) {
        FAIL() << "Can't create thread: " << strerror(ret);
    }

    /* Allow the thread to start */
#ifdef WIN32
    Sleep(1);
#else
    usleep(250);
#endif

    for (ii = 0; ii < 2; ++ii) {
        test_pipeline_hickup_chunk(buffer.data(), buffer.size());
    }

    /* send quit to shut down the read thread ;-) */
    len = raw_command(buffer.data(), buffer.size(), PROTOCOL_BINARY_CMD_QUIT,
                      NULL, 0, NULL, 0);
    safe_send(buffer.data(), len, false);

    cb_join_thread(tid);

    reconnect_to_server(false);
}

TEST_P(McdTestappTest, IOCTL_Get) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    /* NULL key is invalid. */
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_IOCTL_GET, NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_IOCTL_GET,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);
}

TEST_P(McdTestappTest, IOCTL_Set) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    /* NULL key is invalid. */
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_IOCTL_SET, NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_IOCTL_SET,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);

    /* Very long (> IOCTL_KEY_LENGTH) is invalid. */
    {
        char long_key[128 + 1] = {0};
        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_IOCTL_SET, long_key,
                          sizeof(long_key), NULL, 0);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_IOCTL_SET,
                                 PROTOCOL_BINARY_RESPONSE_EINVAL);
    }

    /* release_free_memory always returns OK, regardless of how much was freed.*/
    {
        char cmd[] = "release_free_memory";
        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_IOCTL_SET, cmd, strlen(cmd),
                          NULL, 0);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_IOCTL_SET,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }
}

#if defined(HAVE_TCMALLOC)
TEST_P(McdTestappTest, IOCTL_TCMallocAggrDecommit) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    /* tcmalloc.aggressive_memory_decommit should return zero or one. */
    char cmd[] = "tcmalloc.aggressive_memory_decommit";
    size_t value;
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_IOCTL_GET, cmd, strlen(cmd),
                             NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_IOCTL_GET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    EXPECT_GT(buffer.response.message.header.response.bodylen, 0);
    value = atoi(buffer.bytes + sizeof(buffer.response));
    cb_assert(value == 0 || value == 1);


    /* Check that tcmalloc.aggressive_memory_decommit can be changed, and that
       the value reads correctly. */
    {
        char value_buf[16];
        size_t new_value = 1 - value; /* flip between 1 <-> 0 */
        snprintf(value_buf, sizeof(value_buf), "%zd", new_value);

        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_IOCTL_SET, cmd, strlen(cmd),
                          value_buf, strlen(value_buf));

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_IOCTL_SET,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }
}
#endif /* defined(HAVE_TCMALLOC) */

TEST_P(McdTestappTest, Config_Validate) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    /* identity config is valid. */
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_CONFIG_VALIDATE, NULL, 0,
                             config_string, strlen(config_string));

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    /* empty config is invalid */
    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_CONFIG_VALIDATE, NULL, 0,
                      NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);

    /* non-JSON config is invalid */
    {
        char non_json[] = "[something which isn't JSON]";
        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_CONFIG_VALIDATE, NULL, 0,
                          non_json, strlen(non_json));

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,
                                 PROTOCOL_BINARY_RESPONSE_EINVAL);
    }

    /* 'admin' cannot be changed */
    {
        cJSON *dynamic = cJSON_CreateObject();
        char* dyn_string = NULL;
        cJSON_AddStringToObject(dynamic, "admin", "not_me");
        dyn_string = cJSON_Print(dynamic);
        cJSON_Delete(dynamic);
        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_CONFIG_VALIDATE, NULL, 0,
                          dyn_string, strlen(dyn_string));
        cJSON_Free(dyn_string);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,
                                 PROTOCOL_BINARY_RESPONSE_EINVAL);
    }

    /* 'threads' cannot be changed */
    {
        cJSON *dynamic = cJSON_CreateObject();
        char* dyn_string = NULL;
        cJSON_AddNumberToObject(dynamic, "threads", 99);
        dyn_string = cJSON_Print(dynamic);
        cJSON_Delete(dynamic);
        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_CONFIG_VALIDATE, NULL, 0,
                          dyn_string, strlen(dyn_string));
        cJSON_Free(dyn_string);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,
                                 PROTOCOL_BINARY_RESPONSE_EINVAL);
    }

    /* 'interfaces' - should be able to change max connections */
    {
        cJSON *dynamic = generate_config();
        char* dyn_string = NULL;
        cJSON *iface_list = cJSON_GetObjectItem(dynamic, "interfaces");
        cJSON *iface = cJSON_GetArrayItem(iface_list, 0);
        cJSON_ReplaceItemInObject(iface, "maxconn",
                                  cJSON_CreateNumber(MAX_CONNECTIONS * 2));
        dyn_string = cJSON_Print(dynamic);
        cJSON_Delete(dynamic);
        len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                          PROTOCOL_BINARY_CMD_CONFIG_VALIDATE, NULL, 0,
                          dyn_string, strlen(dyn_string));
        cJSON_Free(dyn_string);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }
}

TEST_P(McdTestappTest, Config_Reload) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    if (GetParam() != Transport::Plain) {
        return;
    }

    /* reload identity config */
    {
        size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD, NULL, 0,
                                 NULL, 0);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    /* Change max_conns on first interface. */
    {
        cJSON *dynamic = generate_config();
        char* dyn_string = NULL;
        cJSON *iface_list = cJSON_GetObjectItem(dynamic, "interfaces");
        cJSON *iface = cJSON_GetArrayItem(iface_list, 0);
        cJSON_ReplaceItemInObject(iface, "maxconn",
                                  cJSON_CreateNumber(MAX_CONNECTIONS * 2));
        dyn_string = cJSON_Print(dynamic);
        cJSON_Delete(dynamic);
        if (write_config_to_file(dyn_string, config_file) == -1) {
            cJSON_Free(dyn_string);
            FAIL() << "Failed to write config to file";
        }
        cJSON_Free(dyn_string);

        size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD, NULL, 0,
                                 NULL, 0);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    /* Change backlog on first interface. */
    {
        cJSON *dynamic = generate_config();
        char* dyn_string = NULL;
        cJSON *iface_list = cJSON_GetObjectItem(dynamic, "interfaces");
        cJSON *iface = cJSON_GetArrayItem(iface_list, 0);
        cJSON_ReplaceItemInObject(iface, "backlog",
                                  cJSON_CreateNumber(BACKLOG * 2));
        dyn_string = cJSON_Print(dynamic);
        cJSON_Delete(dynamic);
        if (write_config_to_file(dyn_string, config_file) == -1) {
            cJSON_Free(dyn_string);
            FAIL() << "Failed to write config to file";
        }
        cJSON_Free(dyn_string);

        size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD, NULL, 0,
                                 NULL, 0);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    /* Change tcp_nodelay on first interface. */
    {
        cJSON *dynamic = generate_config();
        char* dyn_string = NULL;
        cJSON *iface_list = cJSON_GetObjectItem(dynamic, "interfaces");
        cJSON *iface = cJSON_GetArrayItem(iface_list, 0);
        cJSON_AddFalseToObject(iface, "tcp_nodelay");
        dyn_string = cJSON_Print(dynamic);
        cJSON_Delete(dynamic);
        if (write_config_to_file(dyn_string, config_file) == -1) {
            cJSON_Free(dyn_string);
            FAIL() << "Failed to write config to file";
        }
        cJSON_Free(dyn_string);

        size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD, NULL, 0,
                                 NULL, 0);

        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_CONFIG_RELOAD,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    /* Restore original configuration. */
    cJSON *dynamic = generate_config();
    char* dyn_string = cJSON_Print(dynamic);
    cJSON_Delete(dynamic);
    if (write_config_to_file(dyn_string, config_file) == -1) {
        cJSON_Free(dyn_string);
        FAIL() << "Failed to write config to file";
    }
    cJSON_Free(dyn_string);

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_CONFIG_RELOAD, NULL, 0,
                             NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_CONFIG_RELOAD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, Config_Reload_SSL) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    if (GetParam() != Transport::SSL) {
        return;
    }

    /* Change ssl cert/key on second interface. */
    cJSON *dynamic = generate_config();
    char* dyn_string = NULL;
    cJSON *iface_list = cJSON_GetObjectItem(dynamic, "interfaces");
    cJSON *iface = cJSON_GetArrayItem(iface_list, 1);
    cJSON *ssl = cJSON_GetObjectItem(iface, "ssl");

    char pem_path[256];
    char cert_path[256];
    get_working_current_directory(pem_path, 256);
    strncpy(cert_path, pem_path, 256);
    strncat(pem_path, CERTIFICATE_PATH(testapp2.pem), 256);
    strncat(cert_path, CERTIFICATE_PATH(testapp2.cert), 256);

    cJSON_ReplaceItemInObject(ssl, "key", cJSON_CreateString(pem_path));
    cJSON_ReplaceItemInObject(ssl, "cert", cJSON_CreateString(cert_path));
    dyn_string = cJSON_Print(dynamic);
    cJSON_Delete(dynamic);
    if (write_config_to_file(dyn_string, config_file) == -1) {
        cJSON_Free(dyn_string);
        FAIL() << "Failed to write config to file";
    }
    cJSON_Free(dyn_string);

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_CONFIG_RELOAD, NULL, 0,
                             NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_CONFIG_RELOAD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, Audit_Put) {
    union {
        protocol_binary_request_audit_put request;
        protocol_binary_response_audit_put response;
        char bytes[1024];
    }buffer;

    buffer.request.message.body.id = 0;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_AUDIT_PUT, NULL, 0,
                             "{}", 2);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_AUDIT_PUT,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, Audit_ConfigReload) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    }buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_AUDIT_CONFIG_RELOAD,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_AUDIT_CONFIG_RELOAD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}


TEST_P(McdTestappTest, Verbosity) {
    union {
        protocol_binary_request_verbosity request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    int ii;
    for (ii = 10; ii > -1; --ii) {
        size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                 PROTOCOL_BINARY_CMD_VERBOSITY,
                                 NULL, 0, NULL, 0);
        buffer.request.message.header.request.extlen = 4;
        buffer.request.message.header.request.bodylen = ntohl(4);
        buffer.request.message.body.level = (uint32_t)ntohl(ii);
        safe_send(buffer.bytes, len + sizeof(4), false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_VERBOSITY,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }
}

void validate_object(const char *key, const std::string& expected_value) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = raw_command(send.bytes, sizeof(send.bytes),
                             PROTOCOL_BINARY_CMD_GET,
                             key, strlen(key), NULL, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
    char* ptr = receive.bytes + sizeof(receive.response) + 4;
    size_t vallen = receive.response.message.header.response.bodylen - 4;
    std::string actual(ptr, vallen);
    EXPECT_EQ(expected_value, actual);
}

void store_object(const char *key, const char *value) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_BINARY_CMD_SET,
                                 key, strlen(key), value, strlen(value),
                                 0, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    validate_object(key, value);
}

void delete_object(const char* key) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = raw_command(send.bytes, sizeof(send.bytes),
                             PROTOCOL_BINARY_CMD_DELETE, key, strlen(key),
                             NULL, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_DELETE,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, Hello) {
    union {
        protocol_binary_request_hello request;
        protocol_binary_response_hello response;
        char bytes[1024];
    } buffer;
    const char *useragent = "hello world";
    uint16_t features[3];
    uint16_t *ptr;
    size_t len;

    features[0] = htons(PROTOCOL_BINARY_FEATURE_DATATYPE);
    features[1] = htons(PROTOCOL_BINARY_FEATURE_TCPNODELAY);
    features[2] = htons(PROTOCOL_BINARY_FEATURE_MUTATION_SEQNO);

    memset(buffer.bytes, 0, sizeof(buffer.bytes));

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_HELLO,
                      useragent, strlen(useragent), features,
                      sizeof(features));

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_HELLO,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    EXPECT_EQ(6u, buffer.response.message.header.response.bodylen);
    ptr = (uint16_t*)(buffer.bytes + sizeof(buffer.response));
    EXPECT_EQ(PROTOCOL_BINARY_FEATURE_DATATYPE, ntohs(*ptr));
    ptr++;
    EXPECT_EQ(PROTOCOL_BINARY_FEATURE_TCPNODELAY, ntohs(*ptr));
    ptr++;
    EXPECT_EQ(PROTOCOL_BINARY_FEATURE_MUTATION_SEQNO, ntohs(*ptr));

    features[0] = 0xffff;
    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_HELLO,
                             useragent, strlen(useragent), features,
                             2);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_HELLO,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
    EXPECT_EQ(0u, buffer.response.message.header.response.bodylen);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_HELLO,
                             useragent, strlen(useragent), features,
                             sizeof(features) - 1);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_HELLO,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);
}

static void set_feature(const protocol_binary_hello_features feature,
                        bool enable) {
    union {
        protocol_binary_request_hello request;
        protocol_binary_response_hello response;
        char bytes[1024];
    } buffer;
    const char *useragent = "testapp";
    uint16_t wire_feature = htons(feature);
    size_t len = strlen(useragent);

    memset(buffer.bytes, 0, sizeof(buffer));
    buffer.request.message.header.request.magic = PROTOCOL_BINARY_REQ;
    buffer.request.message.header.request.opcode = PROTOCOL_BINARY_CMD_HELLO;
    buffer.request.message.header.request.keylen = htons((uint16_t)len);
    if (enable) {
        buffer.request.message.header.request.bodylen = htonl((uint32_t)len + 2);
    } else {
        buffer.request.message.header.request.bodylen = htonl((uint32_t)len);
    }
    memcpy(buffer.bytes + 24, useragent, len);
    memcpy(buffer.bytes + 24 + len, &wire_feature, 2);

    safe_send(buffer.bytes,
              sizeof(buffer.request) + ntohl(buffer.request.message.header.request.bodylen), false);

    safe_recv(&buffer.response, sizeof(buffer.response));
    len = ntohl(buffer.response.message.header.response.bodylen);
    if (enable) {
        EXPECT_EQ(2u, len);
        safe_recv(&wire_feature, sizeof(wire_feature));
        wire_feature = ntohs(wire_feature);
        EXPECT_EQ(feature, wire_feature);
    } else {
        EXPECT_EQ(0u, len);
    }
}

void set_datatype_feature(bool enable) {
    set_feature(PROTOCOL_BINARY_FEATURE_DATATYPE, enable);
}

static void set_mutation_seqno_feature(bool enable) {
    set_feature(PROTOCOL_BINARY_FEATURE_MUTATION_SEQNO, enable);
}

enum test_return store_object_w_datatype(const char *key,
                                         const void *data, size_t datalen,
                                         bool deflate, bool json)
{
    protocol_binary_request_no_extras request;
    int keylen = (int)strlen(key);
    char extra[8] = { 0 };
    uint8_t datatype = PROTOCOL_BINARY_RAW_BYTES;
    if (deflate) {
        datatype |= PROTOCOL_BINARY_DATATYPE_COMPRESSED;
    }

    if (json) {
        datatype |= PROTOCOL_BINARY_DATATYPE_JSON;
    }

    memset(request.bytes, 0, sizeof(request));
    request.message.header.request.magic = PROTOCOL_BINARY_REQ;
    request.message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
    request.message.header.request.datatype = datatype;
    request.message.header.request.extlen = 8;
    request.message.header.request.keylen = htons((uint16_t)keylen);
    request.message.header.request.bodylen = htonl((uint32_t)(keylen + datalen + 8));
    request.message.header.request.opaque = 0xdeadbeef;

    safe_send(&request.bytes, sizeof(request.bytes), false);
    safe_send(extra, sizeof(extra), false);
    safe_send(key, strlen(key), false);
    safe_send(data, datalen, false);

    union {
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } receive;

    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
    return TEST_PASS;
}

static void get_object_w_datatype(const char *key,
                                  const void *data, size_t datalen,
                                  bool deflate, bool json,
                                  bool conversion)
{
    protocol_binary_response_no_extras response;
    protocol_binary_request_no_extras request;
    int keylen = (int)strlen(key);
    uint32_t flags;
    uint8_t datatype = PROTOCOL_BINARY_RAW_BYTES;
    uint32_t len;

    if (deflate) {
        datatype |= PROTOCOL_BINARY_DATATYPE_COMPRESSED;
    }

    if (json) {
        datatype |= PROTOCOL_BINARY_DATATYPE_JSON;
    }

    memset(request.bytes, 0, sizeof(request));
    request.message.header.request.magic = PROTOCOL_BINARY_REQ;
    request.message.header.request.opcode = PROTOCOL_BINARY_CMD_GET;
    request.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    request.message.header.request.keylen = htons((uint16_t)keylen);
    request.message.header.request.bodylen = htonl(keylen);

    safe_send(&request.bytes, sizeof(request.bytes), false);
    safe_send(key, strlen(key), false);

    safe_recv(&response.bytes, sizeof(response.bytes));
    if (ntohs(response.message.header.response.status != PROTOCOL_BINARY_RESPONSE_SUCCESS)) {
        fprintf(stderr, "Failed to retrieve object!: %d\n",
                (int)ntohs(response.message.header.response.status));
        abort();
    }

    len = ntohl(response.message.header.response.bodylen);
    cb_assert(len > 4);
    safe_recv(&flags, sizeof(flags));
    len -= 4;
    std::vector<char> body(len);
    safe_recv(body.data(), len);

    if (conversion) {
        cb_assert(response.message.header.response.datatype == PROTOCOL_BINARY_RAW_BYTES);
    } else {
        cb_assert(response.message.header.response.datatype == datatype);
    }

    cb_assert(len == datalen);
    cb_assert(memcmp(data, body.data(), body.size()) == 0);
}

TEST_P(McdTestappTest, DatatypeJSON) {
    const char body[] = "{ \"value\" : 1234123412 }";
    set_datatype_feature(true);
    store_object_w_datatype("myjson", body, strlen(body), false, true);

    get_object_w_datatype("myjson", body, strlen(body), false, true, false);

    set_datatype_feature(false);
    get_object_w_datatype("myjson", body, strlen(body), false, true, true);
}

TEST_P(McdTestappTest, DatatypeJSONWithoutSupport) {
    const char body[] = "{ \"value\" : 1234123412 }";
    set_datatype_feature(false);
    store_object_w_datatype("myjson", body, strlen(body), false, false);

    get_object_w_datatype("myjson", body, strlen(body), false, false, false);

    set_datatype_feature(true);
    get_object_w_datatype("myjson", body, strlen(body), false, true, false);
}

/* Compress the specified document, storing the compressed result in the
 * {deflated}.
 * Caller is responsible for free()ing deflated when no longer needed.
 */
size_t compress_document(const char* data, size_t datalen, char** deflated) {

    // Calculate maximum compressed length and allocate a buffer of that size.
    size_t deflated_len = snappy_max_compressed_length(datalen);
    *deflated = (char*)malloc(deflated_len);

    snappy_status status = snappy_compress(data, datalen, *deflated,
                                           &deflated_len);

    cb_assert(status == SNAPPY_OK);

    return deflated_len;
}

TEST_P(McdTestappTest, DatatypeCompressed) {
    const char inflated[] = "aaaaaaaaabbbbbbbccccccdddddd";
    size_t inflated_len = strlen(inflated);
    char* deflated;
    size_t deflated_len = compress_document(inflated, inflated_len, &deflated);

    set_datatype_feature(true);
    store_object_w_datatype("mycompressed", deflated, deflated_len,
                            /*compressed*/true, /*JSON*/false);

    get_object_w_datatype("mycompressed", deflated, deflated_len,
                          true, false, false);

    set_datatype_feature(false);
    get_object_w_datatype("mycompressed", inflated, inflated_len,
                          true, false, true);

    free(deflated);
}

TEST_P(McdTestappTest, DatatypeCompressedJSON) {
    const char inflated[] = "{ \"value\" : \"aaaaaaaaabbbbbbbccccccdddddd\" }";
    size_t inflated_len = strlen(inflated);

    char* deflated;
    size_t deflated_len = compress_document(inflated, inflated_len, &deflated);

    set_datatype_feature(true);

    store_object_w_datatype("mycompressedjson", deflated, deflated_len,
                            /*compressed*/true, /*JSON*/true);

    get_object_w_datatype("mycompressedjson", deflated, deflated_len,
                          true, true, false);

    set_datatype_feature(false);
    get_object_w_datatype("mycompressedjson", inflated, inflated_len,
                          true, true, true);

    free(deflated);
}

TEST_P(McdTestappTest, DatatypeInvalid) {
    protocol_binary_request_no_extras request;
    union {
        protocol_binary_response_no_extras response;
        char buffer[1024];
    } res;
    uint16_t code;

    set_datatype_feature(false);

    memset(request.bytes, 0, sizeof(request));
    request.message.header.request.magic = PROTOCOL_BINARY_REQ;
    request.message.header.request.opcode = PROTOCOL_BINARY_CMD_NOOP;
    request.message.header.request.datatype = 1;

    safe_send(&request.bytes, sizeof(request.bytes), false);
    safe_recv_packet(res.buffer, sizeof(res.buffer));

    code = res.response.message.header.response.status;
    ASSERT_EQ(PROTOCOL_BINARY_RESPONSE_EINVAL, code);

    reconnect_to_server(false);

    set_datatype_feature(false);
    request.message.header.request.datatype = 4;
    safe_send(&request.bytes, sizeof(request.bytes), false);
    safe_recv_packet(res.buffer, sizeof(res.buffer));
    code = res.response.message.header.response.status;
    EXPECT_EQ(PROTOCOL_BINARY_RESPONSE_EINVAL, code);

    reconnect_to_server(false);
}

static uint64_t get_session_ctrl_token(void) {
    union {
        protocol_binary_request_get_ctrl_token request;
        protocol_binary_response_get_ctrl_token response;
        char bytes[1024];
    } buffer;
    uint64_t ret;

    memset(buffer.bytes, 0, sizeof(buffer));
    buffer.request.message.header.request.magic = PROTOCOL_BINARY_REQ;
    buffer.request.message.header.request.opcode = PROTOCOL_BINARY_CMD_GET_CTRL_TOKEN;

    safe_send(buffer.bytes, sizeof(buffer.request), false);
    safe_recv_packet(&buffer.response, sizeof(buffer.bytes));

    cb_assert(htons(buffer.response.message.header.response.status) ==
                PROTOCOL_BINARY_RESPONSE_SUCCESS);

    ret = ntohll(buffer.response.message.header.response.cas);
    cb_assert(ret != 0);

    return ret;
}

static void prepare_set_session_ctrl_token(protocol_binary_request_set_ctrl_token *req,
                                           uint64_t old, uint64_t new_cas)
{
    memset(req, 0, sizeof(*req));
    req->message.header.request.magic = PROTOCOL_BINARY_REQ;
    req->message.header.request.opcode = PROTOCOL_BINARY_CMD_SET_CTRL_TOKEN;
    req->message.header.request.extlen = sizeof(uint64_t);
    req->message.header.request.bodylen = htonl(sizeof(uint64_t));
    req->message.header.request.cas = htonll(old);
    req->message.body.new_cas = htonll(new_cas);
}

TEST_P(McdTestappTest, SessionCtrlToken) {
    union {
        protocol_binary_request_set_ctrl_token request;
        protocol_binary_response_set_ctrl_token response;
        char bytes[1024];
    } buffer;

    uint64_t old_token = get_session_ctrl_token();
    uint64_t new_token = 0x0102030405060708;

    /* Validate that you may successfully set the token to a legal value */
    prepare_set_session_ctrl_token(&buffer.request, old_token, new_token);
    safe_send(buffer.bytes, sizeof(buffer.request), false);
    cb_assert(safe_recv_packet(&buffer.response, sizeof(buffer.bytes)));

    cb_assert(buffer.response.message.header.response.status ==
              PROTOCOL_BINARY_RESPONSE_SUCCESS);
    cb_assert(new_token == ntohll(buffer.response.message.header.response.cas));
    old_token = new_token;

    /* Validate that you can't set it to 0 */
    prepare_set_session_ctrl_token(&buffer.request, old_token, 0);
    safe_send(buffer.bytes, sizeof(buffer.request), false);
    cb_assert(safe_recv_packet(&buffer.response, sizeof(buffer.bytes)));
    cb_assert(buffer.response.message.header.response.status ==
              PROTOCOL_BINARY_RESPONSE_EINVAL);
    cb_assert(old_token == get_session_ctrl_token());

    /* Validate that you can't set it by providing an incorrect cas */
    prepare_set_session_ctrl_token(&buffer.request, old_token + 1, new_token - 1);
    safe_send(buffer.bytes, sizeof(buffer.request), false);
    cb_assert(safe_recv_packet(&buffer.response, sizeof(buffer.bytes)));

    cb_assert(buffer.response.message.header.response.status ==
              PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);
    cb_assert(new_token == ntohll(buffer.response.message.header.response.cas));
    cb_assert(new_token == get_session_ctrl_token());

    /* Validate that you may set it by overriding the cas with 0 */
    prepare_set_session_ctrl_token(&buffer.request, 0, 0xdeadbeef);
    safe_send(buffer.bytes, sizeof(buffer.request), false);
    cb_assert(safe_recv_packet(&buffer.response, sizeof(buffer.bytes)));
    cb_assert(buffer.response.message.header.response.status ==
              PROTOCOL_BINARY_RESPONSE_SUCCESS);
    cb_assert(0xdeadbeef == ntohll(buffer.response.message.header.response.cas));
    cb_assert(0xdeadbeef == get_session_ctrl_token());
}

TEST_P(McdTestappTest, MB_10114) {
    char buffer[512] = {0};
    const char *key = "mb-10114";
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len;

    // Disable ewouldblock_engine - not wanted / needed for this MB regression test.
    ewouldblock_engine_disable();

    store_object(key, "world");
    do {
        len = raw_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_APPEND,
                          key, strlen(key), buffer, sizeof(buffer));
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    } while (receive.response.message.header.response.status == PROTOCOL_BINARY_RESPONSE_SUCCESS);

    cb_assert(receive.response.message.header.response.status == PROTOCOL_BINARY_RESPONSE_E2BIG);

    /* We should be able to delete it */
    len = raw_command(send.bytes, sizeof(send.bytes),
                      PROTOCOL_BINARY_CMD_DELETE,
                      key, strlen(key), NULL, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_DELETE,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

TEST_P(McdTestappTest, DCP_Noop) {
    union {
        protocol_binary_request_dcp_noop request;
        protocol_binary_response_dcp_noop response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_DCP_NOOP,
                             NULL, 0, NULL, 0);

    /*
     * Default engine don't support DCP, so just check that
     * it detects that and if the packet use incorrect format
     */
    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_DCP_NOOP,
                             PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_DCP_NOOP,
                             "d", 1, "f", 1);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_DCP_NOOP,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);
}

TEST_P(McdTestappTest, DCP_BufferAck) {
    union {
        protocol_binary_request_dcp_buffer_acknowledgement request;
        protocol_binary_response_dcp_noop response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT,
                             NULL, 0, "asdf", 4);
    buffer.request.message.header.request.extlen = 4;

    /*
     * Default engine don't support DCP, so just check that
     * it detects that and if the packet use incorrect format
     */
    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT,
                             PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT,
                             "d", 1, "ffff", 4);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT,
                             NULL, 0, "fff", 3);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);
}

TEST_P(McdTestappTest, DCP_Control) {
    union {
        protocol_binary_request_dcp_control request;
        protocol_binary_response_dcp_control response;
        char bytes[1024];
    } buffer;

    size_t len;

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_DCP_CONTROL,
                             "foo", 3, "bar", 3);

    /*
     * Default engine don't support DCP, so just check that
     * it detects that and if the packet use incorrect format
     */
    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_CONTROL,
                             PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_DCP_CONTROL,
                      NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_CONTROL,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_DCP_CONTROL,
                      NULL, 0, "fff", 3);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_CONTROL,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_DCP_CONTROL,
                      "foo", 3, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_DCP_CONTROL,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);
}

TEST_P(McdTestappTest, ISASL_Refresh) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len;

    len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                      PROTOCOL_BINARY_CMD_ISASL_REFRESH,
                      NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_ISASL_REFRESH,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

/*
    Using a memcached protocol extesnsion, shift the time
*/
static void adjust_memcached_clock(uint64_t clock_shift) {
    union {
        protocol_binary_adjust_time request;
        protocol_binary_adjust_time_response response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_ADJUST_TIMEOFDAY,
                             NULL, 0, NULL, 0);

    buffer.request.message.body.offset = htonll(clock_shift);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_ADJUST_TIMEOFDAY,
                                PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

/* expiry, wait1 and wait2 need to be crafted so that
   1. sleep(wait1) and key exists
   2. sleep(wait2) and key should now have expired.
*/
static enum test_return test_expiry(const char* key, time_t expiry,
                                    time_t wait1, int clock_shift) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;

    uint64_t value = 0xdeadbeefdeadcafe;
    size_t len = 0;
    len = storage_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_SET,
                                 key, strlen(key), &value, sizeof(value),
                                 0, (uint32_t)expiry);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    adjust_memcached_clock(clock_shift);

#ifdef WIN32
    Sleep((DWORD)(wait1 * 1000));
#else
    sleep(wait1);
#endif

    memset(send.bytes, 0, 1024);
    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_GET,
                      key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    return TEST_PASS;
}

TEST_P(McdTestappTest, ExpiryRelativeWithClockChangeBackwards) {
    /*
       Just test for MB-11548
       120 second expiry.
       Set clock back by some amount that's before the time we started memcached.
       wait 2 seconds (allow mc time to tick)
       (defect was that time went negative and expired keys immediatley)
    */
    time_t now = time(0);
    test_expiry("test_expiry_relative_with_clock_change_backwards",
                120, 2, (int)(0 - ((now - server_start_time) * 2)));
}

void McdTestappTest::test_set_huge_impl(const char *key, uint8_t cmd,
                                        int result, bool pipeline,
                                        int iterations, int message_size) {

    // This is a large, long test. Disable ewouldblock_engine while
    // running it to speed it up.
    ewouldblock_engine_disable();

    /* some error case may return a body in the response */
    char receive[sizeof(protocol_binary_response_no_extras) + 32];
    const size_t len = message_size + sizeof(protocol_binary_request_set) + strlen(key);
    std::vector<char> set_message(len);
    char* message = set_message.data() + (sizeof(protocol_binary_request_set) + strlen(key));
    int ii;
    memset(message, 0xb0, message_size);

    cb_assert(len == storage_command(set_message.data(), len, cmd, key,
                                     strlen(key), NULL, message_size,
                                     0, 0));

    for (ii = 0; ii < iterations; ++ii) {
        safe_send(set_message.data(), len, false);
        if (!pipeline) {
            if (cmd == PROTOCOL_BINARY_CMD_SET) {
                safe_recv_packet(&receive, sizeof(receive));
                validate_response_header((protocol_binary_response_no_extras*)receive, cmd, result);
            }
        }
    }

    if (pipeline && cmd == PROTOCOL_BINARY_CMD_SET) {
        for (ii = 0; ii < iterations; ++ii) {
            safe_recv_packet(&receive, sizeof(receive));
            validate_response_header((protocol_binary_response_no_extras*)receive, cmd, result);
        }
    }
}

TEST_P(McdTestappTest, SetHuge) {
    test_set_huge_impl("test_set_huge", PROTOCOL_BINARY_CMD_SET,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, false, 10,
                       1023 * 1024);
}

TEST_P(McdTestappTest, SetE2BIG) {
    test_set_huge_impl("test_set_e2big", PROTOCOL_BINARY_CMD_SET,
                       PROTOCOL_BINARY_RESPONSE_E2BIG, false, 10,
                       1024 * 1024);
}

TEST_P(McdTestappTest, SetQHuge) {
    test_set_huge_impl("test_setq_huge", PROTOCOL_BINARY_CMD_SETQ,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, false, 10,
                       1023 * 1024);
}

TEST_P(McdTestappTest, PipelineHuge) {
    test_set_huge_impl("test_pipeline_huge", PROTOCOL_BINARY_CMD_SET,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, true, 200,
                       1023 * 1024);
}

/* support set, get, delete */
void test_pipeline_impl(int cmd, int result, const char* key_root,
                        uint32_t messages_in_stream, size_t value_size) {
    size_t largest_protocol_packet = sizeof(protocol_binary_request_set); /* set has the largest protocol message */
    size_t key_root_len = strlen(key_root);
    size_t key_digit_len = 5; /*append 00001, 00002 etc.. to key_root */
    const size_t buffer_len = (largest_protocol_packet + key_root_len +
                               key_digit_len + value_size) * messages_in_stream;
    size_t out_message_len = 0, in_message_len = 0, send_len = 0, receive_len = 0;
    std::vector<uint8_t> buffer(buffer_len); /* space for creating and receiving a stream */
    std::vector<char> key(key_root_len + key_digit_len + 1); /* space for building keys */
    uint8_t* current_message = buffer.data();
    int session = 0; /* something to stick in opaque */

    session = rand() % 100;

    cb_assert(messages_in_stream <= 99999);

    /* now figure out the correct send and receive lengths */
    if (cmd == PROTOCOL_BINARY_CMD_SET) {
        /* set, sends key and a value */
        out_message_len = sizeof(protocol_binary_request_set) + key_root_len + key_digit_len + value_size;
        /* receives a plain response, no extra */
        in_message_len = sizeof(protocol_binary_response_no_extras);
    } else if (cmd == PROTOCOL_BINARY_CMD_GET) {
        /* get sends key */
        out_message_len = sizeof(protocol_binary_request_get) + key_root_len + key_digit_len;
        /* receives a response + value */
        in_message_len = sizeof(protocol_binary_response_no_extras) + 4 + value_size;

        if (result == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            /* receives a response + flags + value */
            in_message_len = sizeof(protocol_binary_response_no_extras) + 4 + value_size;
        } else {
            /* receives a response + string error */
            in_message_len = sizeof(protocol_binary_response_no_extras) + 9;
        }
    } else if (cmd == PROTOCOL_BINARY_CMD_DELETE) {
        /* delete sends key */
        out_message_len = sizeof(protocol_binary_request_get) + key_root_len + key_digit_len;
        /* receives a plain response, no extra */
        in_message_len = sizeof(protocol_binary_response_no_extras);
    } else {
        FAIL() << "invalid cmd (" << cmd << ") in test_pipeline_impl";
    }

    send_len    = out_message_len * messages_in_stream;
    receive_len = in_message_len * messages_in_stream;

    /* entire buffer and thus any values are 0xaf */
    std::fill(buffer.begin(), buffer.end(), 0xaf);

    for (uint32_t ii = 0; ii < messages_in_stream; ii++) {
        snprintf(key.data(), key_root_len + key_digit_len + 1, "%s%05d", key_root, ii);
        if (PROTOCOL_BINARY_CMD_SET == cmd) {
            protocol_binary_request_set* this_req = (protocol_binary_request_set*)current_message;
            current_message += storage_command((char*)current_message,
                                               out_message_len, cmd,
                                               key.data(), strlen(key.data()),
                                               NULL, value_size, 0, 0);
            this_req->message.header.request.opaque = htonl((session << 8) | ii);
        } else {
            protocol_binary_request_no_extras* this_req = (protocol_binary_request_no_extras*)current_message;
            current_message += raw_command((char*)current_message,
                                           out_message_len, cmd,
                                           key.data(), strlen(key.data()),
                                           NULL, 0);
            this_req->message.header.request.opaque = htonl((session << 8) | ii);
        }
    }

    cb_assert(buffer.size() >= send_len);

    safe_send(buffer.data(), send_len, false);

    std::fill(buffer.begin(), buffer.end(), 0);

    /* and get it all back in the same buffer */
    cb_assert(buffer.size() >= receive_len);

    safe_recv(buffer.data(), receive_len);
    current_message = buffer.data();
    for (uint32_t ii = 0; ii < messages_in_stream; ii++) {
        protocol_binary_response_no_extras* message = (protocol_binary_response_no_extras*)current_message;

        uint32_t bodylen = ntohl(message->message.header.response.bodylen);
        uint8_t  extlen  = message->message.header.response.extlen;
        uint16_t status  = ntohs(message->message.header.response.status);
        uint32_t opq     = ntohl(message->message.header.response.opaque);

        cb_assert(status == result);
        cb_assert(opq == ((session << 8)|ii));

        /* a value? */
        if (bodylen != 0 && result == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            uint8_t* value = current_message + sizeof(protocol_binary_response_no_extras) + extlen;
            for (size_t jj = 0; jj < value_size; jj++) {
                cb_assert(value[jj] == 0xaf);
            }
            current_message = current_message + bodylen + sizeof(protocol_binary_response_no_extras);
        } else {
            current_message = (uint8_t*)(message + 1);
        }
    }
}

TEST_P(McdTestappTest, PipelineSet) {
    // This is a large, long test. Disable ewouldblock_engine while
    // running it to speed it up.
    ewouldblock_engine_disable();

    /*
      MB-11203 would break at iteration 529 where we happen to send 57916 bytes in 1 pipe
      this triggered some edge cases in our SSL recv code.
    */
    for (int ii = 1; ii < 1000; ii++) {
        test_pipeline_impl(PROTOCOL_BINARY_CMD_SET,
                           PROTOCOL_BINARY_RESPONSE_SUCCESS, "key_set_pipe",
                           100, ii);
        test_pipeline_impl(PROTOCOL_BINARY_CMD_DELETE,
                           PROTOCOL_BINARY_RESPONSE_SUCCESS, "key_set_pipe",
                           100, ii);
    }
}

TEST_P(McdTestappTest, PipelineSetGetDel) {
    const char key_root[] = "key_set_get_del";

    // This is a large, long test. Disable ewouldblock_engine while
    // running it to speed it up.
    ewouldblock_engine_disable();

    test_pipeline_impl(PROTOCOL_BINARY_CMD_SET,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, key_root, 5000, 256);

    test_pipeline_impl(PROTOCOL_BINARY_CMD_GET,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, key_root, 5000, 256);

    test_pipeline_impl(PROTOCOL_BINARY_CMD_DELETE,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, key_root, 5000, 256);
}

TEST_P(McdTestappTest, PipelineSetDel) {
    // This is a large, long test. Disable ewouldblock_engine while
    // running it to speed it up.
    ewouldblock_engine_disable();

    test_pipeline_impl(PROTOCOL_BINARY_CMD_SET,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, "key_root",
                       5000, 256);

    test_pipeline_impl(PROTOCOL_BINARY_CMD_DELETE,
                       PROTOCOL_BINARY_RESPONSE_SUCCESS, "key_root",
                       5000, 256);
}

/* Send one character to the SSL port, then check memcached correctly closes
 * the connection (and doesn't hold it open for ever trying to read) more bytes
 * which will never come.
 */
TEST_P(McdTestappTest, MB_12762_SSLHandshakeHang) {

    // Requires SSL.
    if (current_phase != phase_ssl) {
        return;
    }

    /* Setup: Close the existing (handshaked) SSL connection, and create a
     * 'plain' TCP connection to the SSL port - i.e. without any SSL handshake.
     */
    closesocket(sock_ssl);
    sock_ssl = create_connect_plain_socket("127.0.0.1", ssl_port, false);

    /* Send a payload which is NOT a valid SSL handshake: */
    char buf[] = {'a', '\n'};
#if defined(WIN32)
    ssize_t len = send(sock_ssl, buf, (int)sizeof(buf), 0);
#else
    ssize_t len = send(sock_ssl, buf, sizeof(buf), 0);
#endif
    cb_assert(len == 2);

    /* Done writing, close the socket for writing. This triggers the bug: a
     * conn_read -> conn_waiting -> conn_read ... loop in memcached */
#if defined(WIN32)
    int res = shutdown(sock_ssl, SD_SEND);
#else
    int res = shutdown(sock_ssl, SHUT_WR);
#endif
    cb_assert(res == 0);

    /* Check status of the FD - expected to be ready (as it's just been closed
     * by peer), and should not have hit the timeout.
     */
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock_ssl, &fdset);
    struct timeval timeout = {0};
    timeout.tv_sec = 5;
    int ready_fds = select((int)(sock_ssl + 1), &fdset, NULL, NULL, &timeout);
    cb_assert(ready_fds == 1);

    /* Verify that attempting to read from the socket returns 0 (peer has
     * indeed closed the connection).
     */
    len = recv(sock_ssl, buf, 1, 0);
    cb_assert(len == 0);

    /* Restore the SSL connection to a sane state :) */
    reconnect_to_server(false);
}

std::string get_sasl_mechs(void) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t plen = raw_command(buffer.bytes, sizeof(buffer.bytes),
                              PROTOCOL_BINARY_CMD_SASL_LIST_MECHS,
                              NULL, 0, NULL, 0);

    safe_send(buffer.bytes, plen, false);
    safe_recv_packet(&buffer, sizeof(buffer));
    validate_response_header(&buffer.response,
                             PROTOCOL_BINARY_CMD_SASL_LIST_MECHS,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    std::string ret;
    ret.assign(buffer.bytes + sizeof(buffer.response.bytes),
               buffer.response.message.header.response.bodylen);
    return ret;
}


TEST_P(McdTestappTest, SASL_ListMech) {
    std::string mech(get_sasl_mechs());
    EXPECT_NE(0u, mech.size());
}

struct my_sasl_ctx {
    const char *username;
    cbsasl_secret_t *secret;
};

static int sasl_get_username(void *context, int id, const char **result,
                             unsigned int *len)
{
    struct my_sasl_ctx *ctx = reinterpret_cast<struct my_sasl_ctx *>(context);
    if (!context || !result || (id != CBSASL_CB_USER && id != CBSASL_CB_AUTHNAME)) {
        return CBSASL_BADPARAM;
    }

    *result = ctx->username;
    if (len) {
        *len = (unsigned int)strlen(*result);
    }

    return CBSASL_OK;
}

static int sasl_get_password(cbsasl_conn_t *conn, void *context, int id,
                             cbsasl_secret_t **psecret)
{
    struct my_sasl_ctx *ctx = reinterpret_cast<struct my_sasl_ctx *>(context);
    if (!conn || ! psecret || id != CBSASL_CB_PASS || ctx == NULL) {
        return CBSASL_BADPARAM;
    }

    *psecret = ctx->secret;
    return CBSASL_OK;
}

uint16_t McdTestappTest::sasl_auth(const char *username, const char *password) {
    cbsasl_error_t err;
    const char *data;
    unsigned int len;
    const char *chosenmech;
    struct my_sasl_ctx context;
    cbsasl_callback_t sasl_callbacks[4];
    cbsasl_conn_t *client;
    std::string mech(get_sasl_mechs());

    sasl_callbacks[0].id = CBSASL_CB_USER;
    sasl_callbacks[0].proc = (int( *)(void)) &sasl_get_username;
    sasl_callbacks[0].context = &context;
    sasl_callbacks[1].id = CBSASL_CB_AUTHNAME;
    sasl_callbacks[1].proc = (int( *)(void)) &sasl_get_username;
    sasl_callbacks[1].context = &context;
    sasl_callbacks[2].id = CBSASL_CB_PASS;
    sasl_callbacks[2].proc = (int( *)(void)) &sasl_get_password;
    sasl_callbacks[2].context = &context;
    sasl_callbacks[3].id = CBSASL_CB_LIST_END;
    sasl_callbacks[3].proc = NULL;
    sasl_callbacks[3].context = NULL;

    context.username = username;
    context.secret = reinterpret_cast<cbsasl_secret_t*>(calloc(1, 100));
    memcpy(context.secret->data, password, strlen(password));
    context.secret->len = (unsigned long)strlen(password);

    err = cbsasl_client_new(NULL, NULL, NULL, NULL, sasl_callbacks, 0, &client);
    cb_assert(err == CBSASL_OK);
    err = cbsasl_client_start(client, mech.c_str(), NULL, &data, &len, &chosenmech);
    cb_assert(err == CBSASL_OK);

    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t plen = raw_command(buffer.bytes, sizeof(buffer.bytes),
                              PROTOCOL_BINARY_CMD_SASL_AUTH,
                              chosenmech, strlen(chosenmech),
                              data, len);

    safe_send(buffer.bytes, plen, false);
    safe_recv_packet(&buffer, sizeof(buffer));

    bool stepped = false;

    while (buffer.response.message.header.response.status == PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
        stepped = true;
        int datalen = buffer.response.message.header.response.bodylen -
            buffer.response.message.header.response.keylen -
            buffer.response.message.header.response.extlen;

        int dataoffset = sizeof(buffer.response.bytes) +
            buffer.response.message.header.response.keylen +
            buffer.response.message.header.response.extlen;

        err = cbsasl_client_step(client, buffer.bytes + dataoffset, datalen,
                                 NULL, &data, &len);

        plen = raw_command(buffer.bytes, sizeof(buffer.bytes),
                           PROTOCOL_BINARY_CMD_SASL_STEP,
                           chosenmech, strlen(chosenmech), data, len);

        safe_send(buffer.bytes, plen, false);

        safe_recv_packet(&buffer, sizeof(buffer));
    }

    if (stepped) {
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_SASL_STEP,
                                 buffer.response.message.header.response.status);
    } else {
        validate_response_header(&buffer.response,
                                 PROTOCOL_BINARY_CMD_SASL_AUTH,
                                 buffer.response.message.header.response.status);
    }
    free(context.secret);
    cbsasl_dispose(&client);

    return buffer.response.message.header.response.status;
}

TEST_P(McdTestappTest, SASL_Success) {
    EXPECT_EQ(PROTOCOL_BINARY_RESPONSE_SUCCESS,
              sasl_auth("_admin", "password"));
}

TEST_P(McdTestappTest, SASL_Fail) {
    EXPECT_EQ(PROTOCOL_BINARY_RESPONSE_AUTH_ERROR,
              sasl_auth("_admin", "asdf"));
}

TEST_P(McdTestappTest, ExceedMaxPacketSize)
{
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    memset(send.bytes, 0, sizeof(send.bytes));

    storage_command(send.bytes, sizeof(send.bytes),
                    PROTOCOL_BINARY_CMD_SET,
                    "key", 3, NULL, 0, 0, 0);
    send.request.message.header.request.bodylen = ntohl(31*1024*1024);
    safe_send(send.bytes, sizeof(send.bytes), false);

    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_SET,
                             PROTOCOL_BINARY_RESPONSE_EINVAL);

    reconnect_to_server(false);
}

/**
 * Called to refresh memcached's list of usernames and passwords upon bucket
 * creation so authentication can complete correctly and buckets can be
 * connected to.
 */
void refresh_sasl() {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_ISASL_REFRESH,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));

}

/**
 * Called as part of test_topkeys setup, so the stats can be collected from
 * a working bucket.
 */
void create_bucket() {

    union {
        protocol_binary_request_create_bucket req;
        char buffer[1024];
    } request;

    // Bucket name
    const std::string name = "test_bucket";
    // Engine type
    const std::string engine = DEFAULT_ENGINE;
    // Configuratrion string. cache_size == memory allocated
    const std::string config("\0cache_size=1048576;", 23);
    // Combined packet body string
    const std::string args = engine + config;


    FILE *fp = fopen(isasl_file, "a");
    ASSERT_TRUE(fp != NULL);
    fprintf(fp, "%s \n", name.c_str());
    fclose(fp);

    refresh_sasl();

    size_t len = raw_command(request.buffer, sizeof(request.buffer),
                             PROTOCOL_BINARY_CMD_CREATE_BUCKET, name.c_str(),
                             name.size(), args.c_str(), args.size());

    ASSERT_EQ(sasl_auth("_admin", "password"),
              PROTOCOL_BINARY_RESPONSE_SUCCESS);

    safe_send(request.buffer, len, false);


    union {
        protocol_binary_response_no_extras res;
        char buffer[1024];
    } response;

    safe_recv_packet(response.buffer, sizeof(response.buffer));
    validate_response_header(&response.res,
                             PROTOCOL_BINARY_CMD_CREATE_BUCKET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

void delete_bucket() {

    union {
        protocol_binary_request_delete_bucket req;
        char buffer[1024];
    } request;

    const std::string name = "test_bucket";
    const std::string value = "force=true";

    ASSERT_EQ(sasl_auth("_admin", "password"),
              PROTOCOL_BINARY_RESPONSE_SUCCESS);

    size_t len = raw_command(request.buffer, sizeof(request.buffer),
                PROTOCOL_BINARY_CMD_DELETE_BUCKET,
                name.c_str(), name.size(), value.c_str(), value.size());

    safe_send(request.buffer, len, false);

    union {
        protocol_binary_response_no_extras res;
        char buffer[1024];
    } response;

    safe_recv_packet(response.buffer, sizeof(response.buffer));
    validate_response_header(&response.res,
                             PROTOCOL_BINARY_CMD_DELETE_BUCKET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
}

/**
 * Used to throw operations at a bucket so that test_topkeys has a reasonable
 * expected value to assert against.
 */
void populate_bucket(int count) {
    int ii;
    size_t len;


    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    for (ii = 0; ii < count; ii++) {

        len = storage_command(buffer.bytes, sizeof(buffer.bytes),
                              PROTOCOL_BINARY_CMD_SET, "somekey",
                              strlen("someval"), "someval", strlen("someval"),
                              0, 0);

        ASSERT_EQ(sasl_auth("test_bucket", ""),
                  PROTOCOL_BINARY_RESPONSE_SUCCESS);

        safe_send(buffer.bytes, len, false);

        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_SET,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }
}

/**
 * Test for JSON document formatted topkeys (part of bucket_engine). Creates
 * a bucket, populates it, and then calls the topkeys_json stat subcommand
 * against the bucket. Compares returned value against expected value according
 * to populated data.
 */
TEST_P(McdBucketTest, test_topkeys) {

    /* sum used to fill bucket and later check topkeys value against */
    const int sum = 5;
    char *response_string = NULL;

    create_bucket();

    populate_bucket(sum);


    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[2048];
    } buffer;

    memset(buffer.bytes, 0, sizeof(buffer));

    /* Assemble the topkeys_json stat command to the memcached instance
     */
    ASSERT_EQ(sasl_auth("test_bucket", ""), PROTOCOL_BINARY_RESPONSE_SUCCESS);
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_STAT,
                             "topkeys_json", strlen("topkeys_json"),
                             NULL, 0);
    safe_send(buffer.bytes, len, false);

    do {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_STAT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
        if (buffer.response.message.header.response.keylen != 0) {
            response_string = buffer.bytes + (sizeof(buffer.response) +
                     buffer.response.message.header.response.keylen
                     + buffer.response.message.header.response.extlen);
            }
    } while (buffer.response.message.header.response.keylen != 0);


    ASSERT_TRUE(response_string != NULL);

    cJSON *topkeys = cJSON_CreateObject();
    topkeys = cJSON_Parse(response_string);
    int return_value = cJSON_GetObjectItem(cJSON_GetArrayItem(
                            cJSON_GetObjectItem(topkeys, "topkeys"),
                                                0),
                            "access_count")->valueint;
    cJSON_Delete(topkeys);
    ASSERT_EQ(return_value, sum);

    delete_bucket();
}

INSTANTIATE_TEST_CASE_P(PlainOrSSL,
                        McdTestappTest,
                        ::testing::Values(Transport::Plain, Transport::SSL));

INSTANTIATE_TEST_CASE_P(PlainOrSSL,
                        McdBucketTest,
                        ::testing::Values(Transport::Plain, Transport::SSL));

class McdEnvironment : public ::testing::Environment{
public:
    virtual void SetUp() {
        // Create an rbac config file for use for all tests
        cJSON *rbac = generate_rbac_config();
        char *rbac_text = cJSON_Print(rbac);

        strncpy(rbac_file, RBAC_FILE_PATTERN, sizeof(rbac_file));
        ASSERT_NE(cb_mktemp(rbac_file), nullptr);

        ASSERT_EQ(0, write_config_to_file(rbac_text, rbac_file));

        cJSON_Free(rbac_text);
        cJSON_Delete(rbac);
    }

    virtual void TearDown() {
        // Cleanup RBAC config file.
        EXPECT_NE(-1, remove(rbac_file));
    }
};

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    int cmd;
    while ((cmd = getopt(argc, argv, "v")) != EOF) {
        switch (cmd) {
        case 'v':
            memcached_verbose = true;
            break;
        default:
            std::cerr << "Usage: " << argv[0] << " [-v]" << std::endl
                      << std::endl
                      << "  -v Verbose - Print verbose memcached output "
                      << "to stderr.\n" << std::endl;
            return 1;
        }
    }

    McdEnvironment* env = new McdEnvironment();
    ::testing::AddGlobalTestEnvironment(env);

    return RUN_ALL_TESTS();
}
