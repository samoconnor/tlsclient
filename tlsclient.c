#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h> // for setenv
#include <string.h> // for strlen
#include "s2n/api/s2n.h"


struct s2n_config* s2n_config = NULL;

uint8_t s2n_verify_host(
    const char *host_name, size_t host_name_len, void *ctx)
{
    printf("host %s\n", host_name);
    // FIXME
    return 1;
}

int tls_init() {

    assert(s2n_config == NULL);

    // FIXME
    //https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md#client-mode
    setenv("S2N_ENABLE_CLIENT_MODE", "1", 0);

    int r = s2n_init();
    if (r != 0) {
        return r;
    }

    s2n_config = s2n_config_new();
    if (s2n_config == NULL) {
        return -1;
    }

    //r = s2n_config_disable_x509_verification(s2n_config);

    r = s2n_config_set_verify_host_callback(s2n_config, &s2n_verify_host, NULL);
    if (r != 0) {
        return r;
    }
    
    return 0;
}

int tls_connect(char* host, char* port,
                void** tlsout, int* fdout,
                char** errout)
{
    struct addrinfo* ai;
    int r = getaddrinfo(host, port, NULL, &ai);
    if (r != 0) {
        *errout = "GETADDRINFO_ERROR";
        return r;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        *errout = "TCP_ALLOCATION_ERROR";
        return -1;
    }

    r = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (r != 0) {
        *errout = "TCP_CONNECT_ERROR";
        return r;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        *errout = "TCP_FLAGS_ERROR";
        return flags;
    }
    flags |= O_NONBLOCK;
    r = fcntl(fd, F_SETFL, flags);
    if (r != 0) {
        *errout = "TCP_FLAGS_ERROR";
        return r;
    }

    struct s2n_connection *tls = s2n_connection_new(S2N_CLIENT);
    // FIXME s2n_connection_wipe, s2n_connection_free, s2n_shutdown
    if (s2n_config == NULL) {
        *errout = "TLS_ALLOCATION_ERROR";
        return -1;
    }
    r = s2n_connection_set_config(tls, s2n_config);
    if (r != 0) {
        *errout = "TLS_CONFIG_ERROR";
        return r;
    }

    r = s2n_connection_set_fd(tls, fd);
    if (r != 0) {
        *errout = "TLS_CONNECT_ERROR";
        return r;
    }

    *tlsout = (void*)tls;
    *fdout = fd;
    return 0;
}

int tls_negotiate(void* tls, int* blocked) {
    struct s2n_connection *conn = (struct s2n_connection*) tls;

    s2n_blocked_status s2n_blocked;
//printf("neg...\n");
    int r = s2n_negotiate(tls, &s2n_blocked);
//printf("%d %d\n", r, s2n_blocked);
    *blocked = (s2n_blocked != S2N_NOT_BLOCKED);
    return r;
}

int tls_send(void* tls, void* msg, int len,
             int* read_blocked, int* write_blocked)
{
    struct s2n_connection *conn = (struct s2n_connection*) tls;
    s2n_blocked_status blocked;
    int r = s2n_send(conn, msg, len, &blocked);
    *read_blocked = (blocked == S2N_BLOCKED_ON_READ);
    *write_blocked = (blocked == S2N_BLOCKED_ON_READ);
    if (blocked != S2N_NOT_BLOCKED && r < 0) {
        return 0;
    }
    return r;
} 

int tls_recv(void* tls, void* msg, int len, 
             int* read_blocked, int* write_blocked)
{
    struct s2n_connection *conn = (struct s2n_connection*) tls;
    s2n_blocked_status blocked;
    int r = s2n_recv(conn, msg, len, &blocked);
    *read_blocked = (blocked == S2N_BLOCKED_ON_READ);
    *write_blocked = (blocked == S2N_BLOCKED_ON_READ);
    if (blocked != S2N_NOT_BLOCKED && r < 0) {
        return 0;
    }
    return r;
} 


int main() {

    tls_init();

    int fd;
    void* tls;
    char* err = "";
    int r = tls_connect("192.30.255.116", "443", &tls, &fd, &err);
    if (r < 0) {
        exit(r);
    }

    int blocked = 0;
    do {
        r = tls_negotiate(tls, &blocked);
    } while (blocked);
    if (r < 0) {
        printf("negotiate failed!\n");
        exit(r);
    }
    
    char* msg = "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    int l = strlen(msg);
    int n = 0;
    do {
        int readblocked;
        int writeblocked;
        r = tls_send(tls, msg + n, l - n, &readblocked, &writeblocked);
        if (r < 0) {
            printf("send %d\n", r);
            exit(r);
        }
        n += r;
    } while (n < l);
            
    printf("n %d\n", n);

    sleep(1);
    char buf[1000];
    int readblocked;
    int writeblocked;
    r = tls_recv(tls, buf, 1000, &readblocked, &writeblocked);
    if (r < 0) {
        printf("recv %d\n", r);
        exit(r);
    }
    buf[r] = '\0';
    printf("recv %d: %s\n", r, buf);
}

