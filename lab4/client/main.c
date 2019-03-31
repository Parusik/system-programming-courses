#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 512

ssize_t write_buffer(int fd, const char *buffer, size_t size)
{
    size_t bytes_counter;
    bytes_counter = 0;
    while (size > 0)
    {
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

int run_session(int socket_fd)
{
    ssize_t read_count;
    char buffer[BUFFER_SIZE];
    bool need_close;

    need_close = false;
    while (!need_close)
    {
        if (!fgets(buffer, BUFFER_SIZE, stdin))
        {
            return 0;
        }

        if (write_buffer(socket_fd, buffer, strlen(buffer)) < 0)
        {
            perror("Can't send buffer");
            return -1;
        }

        buffer[strcspn(buffer, "\n")] = 0;
        if (!strcmp(buffer, "close"))
        {
            need_close = true;
        }

        read_count = read(socket_fd, buffer, BUFFER_SIZE - 1);
        if (read_count < 0)
        {
            perror("Can't read");
            continue;
        }
        if (read_count == 0)
        {
            puts("Connection closed");
            break;
        }

        buffer[read_count] = 0;
        fputs(buffer, stdout);
    }

    return 0;
}

int main()
{
    int socket_fd;
    struct sockaddr_in addr;
    int exit_status;

    exit_status = EXIT_FAILURE;

    addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    addr.sin_port = htons(3218);
    addr.sin_family = AF_INET; //socket type AF_UNIX

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("Can't create socket");
        goto EXIT;
    }

    if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        perror("Can't connect to specified socket");
        goto CLOSE_SOCKET;
    }

    if (run_session(socket_fd) < 0)
    {
        goto CLOSE_SOCKET;
    }

    exit_status = EXIT_SUCCESS;

CLOSE_SOCKET:
    if (close(socket_fd < 0))
    {
        perror("Can't close socket");
    }
EXIT:
    exit(exit_status);
}
