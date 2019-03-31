#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Max buffer size is 1024 and 1 byte for \0
#define BUFF_SIZE (1024 + 1)
#define EPOLL_5SECONDS (5 * 1000)

int main(int argc, char* argv[])
{
    int exit_code;
    int epollfd;
    struct epoll_event ev;
    char* buffer;

    exit_code = EXIT_FAILURE;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s ID\n", argv[0]);
        goto EXIT;
    }

    buffer = malloc(BUFF_SIZE);

    epollfd = epoll_create1(0);
    if (epollfd < 0) {
        perror("Can't create epoll");
        goto CLEANUP_BUFFER;
    }

    ev.events = EPOLLIN;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) != 0) {
        perror("Can't add stdin to epoll");
        goto CLEANUP_EPOLL;
    }

    while (1) {
        int epoll_res;

        epoll_res = epoll_wait(epollfd, &ev, 1, EPOLL_5SECONDS);
        if (epoll_res < 0) {
            perror("epoll_wait()");
            goto CLEANUP_EPOLL;
        }
        if (epoll_res == 0) { // No input
            printf("%s no input for 5 sec\n", argv[1]);
        }
        if (epoll_res > 0) {
            if (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
                printf("%s got: %s", argv[1], buffer);
            } else { // fgets returns NULL
                puts("Exiting...");
                break;
            }
        }
    }

    exit_code = EXIT_SUCCESS;

CLEANUP_EPOLL:
    if (close(epollfd) != 0) {
        perror("Can't close epoll instance");
        exit_code = EXIT_FAILURE;
    }

CLEANUP_BUFFER:
    free(buffer);

EXIT:
    exit(exit_code);
}
