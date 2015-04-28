#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <evutil.h>
#include <snappy-c.h>
#include <cJSON.h>

#include "daemon/cache.h"
#include <memcached/util.h>
#include <memcached/config_parser.h>
#include <cbsasl/cbsasl.h>
// #include "extensions/protocol/fragment_rw.h"
#include "extensions/protocol/testapp_extension.h"
#include <platform/platform.h>
#include "memcached/openssl.h"
#include "programs/utilities.h"

#ifdef WIN32
#include <process.h>
#define getpid() _getpid()
#endif

static uint8_t read_command = 0xe1;
static uint8_t write_command = 0xe2;

static cJSON *json_config = NULL;
const char *config_string = NULL;
char config_file[] = "memcached_testapp.json.XXXXXX";
char rbac_file[] = "testapp_rbac.json.XXXXXX";

#define TMP_TEMPLATE "testapp_tmp_file.XXXXXX"

#define MAX_CONNECTIONS 1000
#define BACKLOG 1024

enum test_return { TEST_SKIP, TEST_PASS, TEST_FAIL };

// Removed phases (setup, plain, ssl, cleanup)
#define phase_setup 0x1
#define phase_plain 0x2
#define phase_ssl 0x4
#define phase_cleanup 0x8

#define phase_max 4
static int current_phase = 0;

static int phases_enabled = phase_setup | phase_plain | phase_ssl | phase_cleanup;

static pid_t server_pid;
static in_port_t port = -1;
static in_port_t ssl_port = -1;
static SOCKET sock;
static SOCKET sock_ssl; 	// FIXME?
static bool allow_closed_read = false; //FIXME?
static time_t server_start_time; //FIXME?
static SSL_CTX *ssl_ctx = NULL;
static SSL *ssl = NULL;
static BIO *ssl_bio_r = NULL;
static BIO *ssl_bio_w = NULL;

static void set_mutation_seqno_feature(bool enable);

static bool phase_enabled(int phase) {
	return phases_enabled & phase;
}

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

static cJSON *generate_config(char *engine)
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

	cJSON_AddStringToObject(obj, "module", ("%s_engine.so", engine));    // TODO:: check is definitely to change elsewhere
	cJSON_AddItemReferenceToObject(root, "engine", obj);

	obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "module", "blackhole_logger.so");
	cJSON_AddItemToArray(array, obj);
	obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "module", "fragment_rw_ops.so");
	cJSON_AddStringToObject(obj, "config", "r=225;w=226");
	cJSON_AddItemToArray(array, obj);
	obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "module", "testapp_extension.so");
	cJSON_AddItemToArray(array, obj);

	cJSON_AddItemReferenceToObject(root, "extensions", array);

	array = cJSON_CreateArray();
	obj = cJSON_CreateObject();
	obj_ssl = cJSON_CreateObject();

#ifdef WIN32
	cJSON_AddNumberToObject(obj, "port", 11211);
#else
	cJSON_AddNumberToObject(obj, "port", 0);
#endif
	cJSON_AddNumberToObject(obj, "maxconn", MAX_CONNECTIONS);
	cJSON_AddNumberToObject(obj, "backlog", BACKLOG);
	cJSON_AddStringToObject(obj, "host", "*");
	cJSON_AddItemToArray(array, obj);

	if (phase_enabled(phase_ssl)) {
		obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(obj, "port", 11996);
		cJSON_AddNumberToObject(obj, "maxconn", MAX_CONNECTIONS);
		cJSON_AddNumberToObject(obj, "backlog", BACKLOG);
		cJSON_AddStringToObject(obj, "host", "*");
		cJSON_AddItemToObject(obj, "ssl", obj_ssl = cJSON_CreateObject());
		cJSON_AddStringToObject(obj_ssl, "key", pem_path);
		cJSON_AddStringToObject(obj_ssl, "cert", cert_path);
		cJSON_AddItemToArray(array, obj);
	}
	cJSON_AddItemReferenceToObject(root, "interfaces", array);

	cJSON_AddStringToObject(root, "admin", "");
	cJSON_AddTrueToObject(root, "datatype_support");
	cJSON_AddStringToObject(root, "rbac_file", rbac_path);

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
	cJSON_AddItemReferenceToObject(prof, "memcached", obj);
	cJSON_AddItemToArray(array, prof);

	prof = cJSON_CreateObject();
	cJSON_AddStringToObject(prof, "name", "statistics");
	cJSON_AddStringToObject(prof, "description", "only stat and assume");
	obj = cJSON_CreateObject();

	array2 = cJSON_CreateArray();
	cJSON_AddItemToArray(array2, cJSON_CreateString("stat"));
	cJSON_AddItemToArray(array2, cJSON_CreateString("assume_role"));
	cJSON_AddItemReferenceToObject(obj, "allow", array2);
	cJSON_AddItemReferenceToObject(prof, "memcached", obj);
	cJSON_AddItemToArray(array, prof);

	cJSON_AddItemReferenceToObject(root, "profiles", array);

	/* roles */
	array = cJSON_CreateArray();
	prof = cJSON_CreateObject();
	cJSON_AddStringToObject(prof, "name", "statistics");
	cJSON_AddStringToObject(prof, "profiles", "statistics");

	cJSON_AddItemToArray(array, prof);
	cJSON_AddItemReferenceToObject(root, "roles", array);

	/* users */
	array = cJSON_CreateArray();
	prof = cJSON_CreateObject();
	cJSON_AddStringToObject(prof, "login", "*");
	cJSON_AddStringToObject(prof, "profiles", "system");
	cJSON_AddStringToObject(prof, "roles", "statistics");

	cJSON_AddItemToArray(array, prof);
	cJSON_AddItemReferenceToObject(root, "users", array);

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

#ifdef WIN32
static HANDLE start_server(in_port_t *port_out, in_port_t *ssl_port_out, bool daemon, int timeout) {
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	char *commandline = malloc(1024);
	char env[80];
	sprintf_s(env, sizeof(env), "MEMCACHED_PARENT_MONITOR=%u", GetCurrentProcessId());
	putenv(env);

	memset(&sinfo, 0, sizeof(sinfo));
	memset(&pinfo, 0, sizeof(pinfo));
	sinfo.cb = sizeof(sinfo);

	sprintf(commandline, "memcached.exe -C %s", config_file);

	if (!CreateProcess("memcached.exe",
					commandline,
					NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo)) {
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
	/* Do a short sleep to let the other process to start */
	Sleep(1);
	CloseHandle(pinfo.hThread);

	*port_out = 11211;
	*ssl_port_out = 11996;
	return pinfo.hProcess;
}
#else
/**
* Function to start the server and let it listen on a random port
*
* @param port_out where to store the TCP port number the server is
*                 listening on
* @param daemon set to true if you want to run the memcached server
*               as a daemon process
* @return the pid of the memcached server
*/

static pid_t start_server(in_port_t *port_out, in_port_t *ssl_port_out, bool daemon, int timeout) {
	printf("call fine\n");	//FIXME
	char environment[80];
	char *filename= environment + strlen("MEMCACHED_PORT_FILENAME=");
#ifdef __sun
	char coreadm[128];
#endif
	pid_t pid;
	FILE *fp;
	char buffer[80];

	char env[80];
	snprintf(env, sizeof(env), "MEMCACHED_PARENT_MONITOR=%lu", (unsigned long)getpid());
	putenv(env);

	snprintf(environment, sizeof(environment),
			"MEMCACHED_PORT_FILENAME=/tmp/ports.%lu", (long)getpid());
	remove(filename);

#ifdef __sun
	/* I want to name the corefiles differently so that they don't
	overwrite each other
	*/
	snprintf(coreadm, sizeof(coreadm),
			"coreadm -p core.%%f.%%p %lu", (unsigned long)getpid());
	system(coreadm);
#endif

	pid = fork();
	cb_assert(pid != -1);
	printf("cb_assert(pid [%i]) fine\n", pid);	//FIXME

	if (pid == 0) {
		printf("forking intensifies [%i]\n", pid);	//FIXME
		/* Child */
		char *argv[20];
		int arg = 0;
		char tmo[24];

		snprintf(tmo, sizeof(tmo), "%u", timeout);
		putenv(environment);

		if (getenv("RUN_UNDER_VALGRIND") != NULL) {
			printf("VALGRIND\n");
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
		printf("%s\n", (char*)config_file);
		argv[arg++] = NULL;
		printf("pre assert [%i]\n", pid);	//FIXME
		cb_assert(execvp(argv[0], argv) != -1);
		printf("cb_assert(inif) fine\n");	//FIXME
	}

	/* Yeah just let us "busy-wait" for the file to be created ;-) */
	while (access(filename, F_OK) == -1) {
		usleep(10);
	}

	printf("opening [%i]\n", pid);	//FIXME
	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open the file containing port numbers: %s\n",
				strerror(errno));
		cb_assert(false);
	}

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
	cb_assert(remove(filename) == 0);

	return pid;
}
#endif

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

static void connect_to_server_plain(in_port_t port, bool nonblocking) {
	sock = create_connect_plain_socket("127.0.0.1", port, nonblocking);

	if (nonblocking) {
		if (evutil_make_socket_nonblocking(sock) == -1) {
			fprintf(stderr, "evutil_make_socket_nonblocking failed\n");
			abort();
		}
	}
}

static void reconnect_to_server(bool nonblocking) {
	// if (current_phase == phase_ssl) {
	// 	closesocket(sock_ssl);
	// 	connect_to_server_ssl(ssl_port, nonblocking);
	// } else {
	closesocket(sock);
	connect_to_server_plain(port, nonblocking);
	// }
}

static enum test_return test_vperror(void) {
#ifdef WIN32
	return TEST_SKIP;
#else
	int rv = 0;
	int oldstderr = dup(STDERR_FILENO);
	char tmpl[sizeof(TMP_TEMPLATE)+1];
	int newfile;
	char buf[80] = {0};
	FILE *efile;
	char *prv;
	char expected[80] = {0};

	strncpy(tmpl, TMP_TEMPLATE, sizeof(TMP_TEMPLATE)+1);

	newfile = mkstemp(tmpl);
	cb_assert(newfile > 0);
	rv = dup2(newfile, STDERR_FILENO);
	cb_assert(rv == STDERR_FILENO);
	rv = close(newfile);
	cb_assert(rv == 0);

	errno = EIO;
	vperror("Old McDonald had a farm.  %s", "EI EIO");

	/* Restore stderr */
	rv = dup2(oldstderr, STDERR_FILENO);
	cb_assert(rv == STDERR_FILENO);


	/* Go read the file */
	efile = fopen(tmpl, "r");
	cb_assert(efile);
	prv = fgets(buf, sizeof(buf), efile);
	cb_assert(prv);
	fclose(efile);

	unlink(tmpl);

	snprintf(expected, sizeof(expected),
			"Old McDonald had a farm.  EI EIO: %s\n", strerror(EIO));

	/*
	fprintf(stderr,
			"\nExpected:  ``%s''"
			"\nGot:       ``%s''\n", expected, buf);
	*/

	return strcmp(expected, buf) == 0 ? TEST_PASS : TEST_FAIL;
#endif
}

static char* trim(char* ptr) {
	char *start = ptr;
	char *end;

	while (isspace(*start)) {
		++start;
	}
	end = start + strlen(start) - 1;
	if (end != start) {
		while (isspace(*end)) {
			*end = '\0';
			--end;
		}
	}
	return start;
}

static char *isasl_file;

static enum test_return start_memcached_server(void) {
	cJSON *rbac = generate_rbac_config();
	char *rbac_text = cJSON_Print(rbac);
	printf("rbac OK\n");
	if (cb_mktemp(rbac_file) == NULL) {
		return TEST_FAIL;
	}
	if (write_config_to_file(rbac_text, rbac_file) == -1) {
		return TEST_FAIL;
	}
	printf("rbac PASS\n");
	cJSON_Free(rbac_text);
	cJSON_Delete(rbac);

	json_config = generate_config();
	config_string = cJSON_Print(json_config);
	printf("JSON intensifies\n");
	if (cb_mktemp(config_file) == NULL) {
		return TEST_FAIL;
	}
	if (write_config_to_file(config_string, config_file) == -1) {
		return TEST_FAIL;
	}
	printf("JSON pass\n");

	char fname[1024];
	snprintf(fname, sizeof(fname), "isasl.%lu.%lu.pw",
			(unsigned long)getpid(),
			(unsigned long)time(NULL));
	isasl_file = strdup(fname);
	printf("iasl assert\n");
	cb_assert(isasl_file != NULL);
	printf("iasl fine\n");

	FILE *fp = fopen(isasl_file, "w");
	cb_assert(fp != NULL);
	printf("fp fine\n");
	fprintf(fp, "_admin password \n");
	fclose(fp);
	char env[1024];
	snprintf(env, sizeof(env), "ISASL_PWFILE=%s", isasl_file);
	putenv(strdup(env));

	server_start_time = time(0);
	printf("=== starting server ===\n");
	server_pid = start_server(&port, &ssl_port, false, 600);
	return TEST_PASS;
}

static off_t raw_command(char* buf,
						size_t bufsz,
						uint8_t cmd,
						const void* key,
						size_t keylen,
						const void* dta,
						size_t dtalen) {
	/* all of the storage commands use the same command layout */
	off_t key_offset;
	protocol_binary_request_no_extras *request = (void*)buf;
	cb_assert(bufsz >= sizeof(*request) + keylen + dtalen);

	memset(request, 0, sizeof(*request));
	if (cmd == read_command || cmd == write_command) {
		request->message.header.request.extlen = 8;
	} else if (cmd == PROTOCOL_BINARY_CMD_AUDIT_PUT) {
		request->message.header.request.extlen = 4;
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

static ssize_t phase_send(const void *buf, size_t len) {
	ssize_t rv = 0, send_rv = 0;
	if (current_phase == phase_ssl) {
		long send_len = 0;
		char *send_buf = NULL;
		/* push the data through SSL into the BIO */
		rv = (ssize_t)SSL_write(ssl, (const char*)buf, (int)len);
		send_len = BIO_get_mem_data(ssl_bio_w, &send_buf);

#ifdef WIN32
		send_rv = send(sock_ssl, send_buf, (int)send_len, 0);
#else
		send_rv = send(sock_ssl, send_buf, send_len, 0);
#endif

		if (send_rv > 0) {
			cb_assert(send_len == send_rv);
			(void)BIO_reset(ssl_bio_w);
		} else {
			/* flag failure to user */
			rv = send_rv;
		}
	} else {
#ifdef WIN32
		rv = send(sock, buf, (int)len, 0);
#else
		rv = send(sock, buf, len, 0);
#endif
	}
	return rv;
}

static ssize_t phase_recv(void *buf, size_t len) {

	ssize_t rv = 0;
	if (current_phase == phase_ssl) {
		/* can we read some data? */
		while((rv = SSL_peek(ssl, buf, (int)len)) == -1)
		{
			/* nope, keep feeding SSL until we can */
#ifdef WIN32
			rv = recv(sock_ssl, buf, (int)len, 0);
#else
			rv = recv(sock_ssl, buf, len, 0);
#endif

			if(rv > 0) {
				/* write into the BIO what came off the network */
				BIO_write(ssl_bio_r, buf, rv);
			} else if(rv == 0) {
				return rv; /* peer closed */
			}
		}
		/* now pull the data out and return */
		rv = SSL_read(ssl, buf, (int)len);
	}
	else {
#ifdef WIN32
		rv = recv(sock, buf, (int)len, 0);
#else
		rv = recv(sock, buf, len, 0);
#endif
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


static void safe_send(const void* buf, size_t len, bool hickup)
{
	off_t offset = 0;
	const char* ptr = buf;
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
	off_t offset = 0;
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

static bool safe_recv_packet(void *buf, size_t size) {
	protocol_binary_response_no_extras *response = buf;
	char *ptr;
	size_t len;

	cb_assert(size >= sizeof(*response));
	if (!safe_recv(response, sizeof(*response))) {
		return false;
	}
	response->message.header.response.keylen = ntohs(response->message.header.response.keylen);
	response->message.header.response.status = ntohs(response->message.header.response.status);
	response->message.header.response.bodylen = ntohl(response->message.header.response.bodylen);

	len = sizeof(*response);
	ptr = buf;
	ptr += len;
	cb_assert(size >= (sizeof(*response) + response->message.header.response.bodylen));
	if (!safe_recv(ptr, response->message.header.response.bodylen)) {
		return false;
	}

	return true;
}

static off_t storage_command(char*buf,
							size_t bufsz,
							uint8_t cmd,
							const void* key,
							size_t keylen,
							const void* dta,
							size_t dtalen,
							uint32_t flags,
							uint32_t exp) {
	/* all of the storage commands use the same command layout */
	off_t key_offset;
	protocol_binary_request_set *request = (void*)buf;
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

	return (off_t)(key_offset + keylen + dtalen);
}

static bool create_bucket() {

	// char buf[1024];
	// snprintf(buf, sizeof(buf), "%s%c%s", path, 0, args);
	// return create_packet4(PROTOCOL_BINARY_CMD_CREATE_BUCKET, user,
	//                       buf, strlen(path) + strlen(args) + 1, 0);

	union {
		protocol_binary_request_no_extras request;
		protocol_binary_response_no_extras response;
		char bytes[1024];
	} buffer;

	char *user = "someuser";
	char *path /* = ENGINE_PATH*/;
	char *args = "";

	size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
							PROTOCOL_BINARY_CMD_CREATE_BUCKET,
							user, strlen(user), NULL, 0);
					// was 	buffer,
					// 		(strlen(path) + strlen(args) + 1));


//               raw_command(buf,        bufsz,
//                           cmd,
//                           key, keylen, dta, dtalen)
	safe_send(buffer.bytes, len, false);
	// printf(buf, sizeof(buf), "%s%c%s", path, 0, args);
	// PROTOCOL_BINARY_CMD_CREATE_BUCKET

}

// static bool uncreate_bucket() {
//
// }

static enum test_return test_topkeys(void) {
	// for (int ii = 0; ii < 10; ii++) {
	//     test_set_impl("samplekey", PROTOCOL_BINARY_CMD_SET);
	// }
	// test_get_impl("samplekey", PROTOCOL_BINARY_CMD_GET); // FIXME SOMEHOW
	// test_getq_impl("samplekey", PROTOCOL_BINARY_CMD_GETQ);

	if (create_bucket()) {

	union {
		protocol_binary_request_no_extras request;
		protocol_binary_response_no_extras response;
		char bytes[2048];
	} buffer;

	size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
							PROTOCOL_BINARY_CMD_STAT,
							"topkeys_json", strlen("topkeys_json"), NULL, 0);

	safe_send(buffer.bytes, len, false);
	// do {
	//     safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
	//     validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_STAT,
	//                              PROTOCOL_BINARY_RESPONSE_SUCCESS);
	//     // printf("\n%s\n", buffer.response.message.header.response.status);
	// } while (buffer.response.message.header.response.keylen != 0);

	// cb_assert(strstr(buffer.response.message.header.response.value, "\"access_count\":10"));

	return TEST_PASS;

	} else {

		return TEST_FAIL;

	}
}

typedef enum test_return (*TEST_FUNC)(void);
struct testcase {
	const char *description;
	TEST_FUNC function;
	const int phases;	//FIXME
};

/* FIXME FIXME FIXME */
#define TESTCASE_SETUP(desc, func) {desc, func, phase_setup}
#define TESTCASE_PLAIN(desc, func) {desc, func, phase_plain}
#define TESTCASE_PLAIN_AND_SSL(desc, func) {desc, func, (phase_plain|phase_ssl)}
#define TESTCASE_SSL(desc, func) {desc, func, phase_ssl}
#define TESTCASE_CLEANUP(desc, func) {desc, func, phase_cleanup}

struct testcase testcases[] = {
	TESTCASE_SETUP("start_server", start_memcached_server),
	TESTCASE_PLAIN("topkeys", test_topkeys),
	TESTCASE_PLAIN(NULL, NULL)
};

int main(int argc, char **argv) {

	int exitcode = 0;
	int ii = 0;
	enum test_return ret;

	// int test_phase_order[] = {phase_setup, phase_plain, phase_ssl, phase_cleanup};
	// char* test_phase_strings[] = {"setup", "plain", "SSL", "cleanup"};

	cb_initialize_sockets();
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	for (ii = 0; testcases[ii].description != NULL; ++ii) {
		int jj;

		fprintf(stdout, "\r");
		for (jj = 0; jj < 60; ++jj) {
			fprintf(stdout, " ");
		}
		fprintf(stdout, "\rRunning %04d %s - ", ii + 1, testcases[ii].description);
		fflush(stdout);
		ret = testcases[ii].function();
		if (ret = TEST_SKIP) {
			fprintf(stdout, " SKIP\n");
		} else if (ret != TEST_PASS) {
			fprintf(stdout, " FAILED\n");
			exitcode = 1;
		}
		fflush(stdout);
	}

	fprintf(stdout, "\r             \n");
	return exitcode;
}
