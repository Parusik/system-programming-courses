#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

// Max buffer size is 1024 and 1 byte for \0
#define BUFF_SIZE (1024 + 1)

int main(int argc, char* argv[])
{
    char buffer[BUFF_SIZE];
    fd_set rfds;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s ID\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int retval;
        struct timeval tv;

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        //Initializes the file descriptor set fdset to have zero bits for all file descriptors.
        FD_SET(STDIN_FILENO, &rfds);
        //Sets the bit for the file descriptor fd in the file descriptor set fdset.

        retval = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
        //int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
        // nfds  is the highest-numbered file descriptor in any of the three  sets,plus 1.

        if (retval < 0) {
            perror("select()");
            exit(EXIT_FAILURE);
        }

        if (retval == 0) {
            printf("%s no input for 5 sec\n", argv[1]);
        }

        if (retval > 0) {
            // STDIN_FILENO is the only descriptor in set, no need to check FD_ISSET
            if (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
                printf("%s got: %s", argv[1], buffer);
            } else { // fgets returns NULL
                puts("Exiting..."); 
                break;
            }
        }
    }

    exit(EXIT_FAILURE);
}
