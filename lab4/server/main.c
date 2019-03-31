#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int log_fd;

ssize_t write_buffer(int fd, const char* buffer, size_t size)
{
    size_t bytes_counter;
    bytes_counter = 0;
    while (size > 0) {
        ssize_t bytes_written;
        bytes_written = write(fd, buffer, size);
        if (bytes_written < 0)
            return -1;
        buffer += bytes_written;
        size -= bytes_written;
        bytes_counter += bytes_written;
    }
    return bytes_counter;
}

ssize_t log_info(const char* msg)
{
    time_t t;
    char time_buffer[64];
    char buffer[512];
    int msg_len;

    time(&t);
    strftime(time_buffer, 64, "%c", localtime(&t));

    msg_len = snprintf(buffer, 512, "[%s] INFO  %s", time_buffer, msg);
    return write_buffer(log_fd, buffer, msg_len);
}

ssize_t log_error(const char* msg)
{
    time_t t;
    char buffer[512];
    char time_buffer[64];
    int msg_len;

    time(&t);

    strftime(time_buffer, 64, "%c", localtime(&t));

    msg_len = snprintf(buffer, 512, "[%s] ERROR %s: %s\n", time_buffer, msg, strerror(errno));
    return write_buffer(log_fd, buffer, msg_len);
}

void run_session(int client_socket, struct sockaddr_in* client_addr)
{
    time_t t;
    char ip_buffer[INET_ADDRSTRLEN];
    bool need_close;

    inet_ntop(AF_INET, (&client_addr->sin_addr), ip_buffer, INET_ADDRSTRLEN);

    need_close = false;
    while (!need_close) {
        char in_buff[256];
        char out_buff[512];
        char time_buffer[64];
        ssize_t read_bytes;
        int msg_len;

        read_bytes = read(client_socket, in_buff, 255);
        if (read_bytes < 0) {
            snprintf(out_buff, 512, "Error during reading data from %s", ip_buffer);
            log_error(out_buff);
            break;
        }   
        if (read_bytes == 0) { //client exit 
            snprintf(out_buff, 512, "%s disconnected\n", ip_buffer);
            log_info(out_buff);
            break;
        }

        in_buff[read_bytes] = '\0';

        if (!strcmp(in_buff, "close\r\n") || !strcmp(in_buff, "close\n")) {
            snprintf(out_buff, 512, "Closing session with %s\n", ip_buffer);
            log_info(out_buff);
            need_close = true;
        }

        time(&t);
        strftime(time_buffer, 64, "%c", localtime(&t));
        msg_len = snprintf(out_buff, 512, "(%jd) [%s]: %s", (intmax_t)getpid(), time_buffer, in_buff);
        if (write_buffer(client_socket, out_buff, msg_len) < 0) {
            snprintf(out_buff, 512, "Error happaned while sending data to %s", ip_buffer);
            log_error(out_buff);
            break;
        }
    }

    if (close(client_socket) < 0) {
        log_error("Can't close client socket");
    }
}

int run_server(int port)
{
    int server_socket;
    struct sockaddr_in addr, client_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        log_error("Can't open socket");
        return -1;
    }
    log_info("Opened socket\n");

    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Can't bind socket");
        return -1;
    }
    log_info("Bound socket\n");

    if (listen(server_socket, 5) < 0) {
        log_error("Can't listen socket");
        return -1;
    }
    log_info("Started listening to socket\n");

    while (1) {
        int client_socket;
        char ip_buffer[INET_ADDRSTRLEN];
        char buffer[256];
        socklen_t size;

        size = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &size); //waiting for 
        if (client_socket < 0) {
            log_error("Can't accept client");
            continue;
        }

        inet_ntop(AF_INET, (&client_addr.sin_addr), ip_buffer, INET_ADDRSTRLEN);
        snprintf(buffer, 256, "Accepted connection from %s\n", ip_buffer);
        log_info(buffer);

        if (!fork()) { //In child
            run_session(client_socket, &client_addr);
            exit(EXIT_SUCCESS);
        }
        if (close(client_socket) < 0) {
            log_error("Error during socket close()");
        }
    }
}

int main()
{
    pid_t pid;
    int parent_fds[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
    int exit_code;

    exit_code = EXIT_FAILURE;

/* 
        DEAMON
 */

    pid = fork();
    if (pid < 0) {
        perror("Can't fork");
        goto EXIT;
    }
    if (pid > 0) { // In parent
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        perror("Can't create session");
        goto EXIT;
    }

    pid = fork();
    if (pid < 0) {
        perror("Can't fork second time");
        goto EXIT;
    }
    if (pid > 0) { //In parent after 2 fork
        exit(EXIT_SUCCESS);
    }

    if (chdir("/") < 0) {
        perror("Can't change directory to root");
        goto EXIT;
    }

    for (int i = 0; i < 3; i++) {
        if (close(parent_fds[i]) < 0) {
            perror("Can't close parent FD");
            goto EXIT;
        }
    }

    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+");

    /* END */

    log_fd = open("/tmp/server.log", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (log_fd < 0) {
        perror("Can't open log");
        goto EXIT;
    }

    if (run_server(3218) < 0) {
        char* msg = "Error happaned when running server, exiting\n";
        write_buffer(log_fd, msg, strlen(msg));
        goto CLOSE_LOG;
    }

    exit_code = EXIT_SUCCESS;

CLOSE_LOG:
    close(log_fd);
EXIT:
    exit(exit_code);
}
