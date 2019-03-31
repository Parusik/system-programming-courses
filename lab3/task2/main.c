#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFF_SIZE 1024
#define SHM_NAME "/datum"

typedef struct {
    time_t time;
    pid_t pid;
    char msg[BUFF_SIZE];
} datum;

int main()
{
    int shm_fd;
    int exit_code;
    datum* shm_datum;
    bool shm_created;

    exit_code = EXIT_FAILURE;

    shm_created = false;
    shm_fd = shm_open(SHM_NAME, O_RDWR, 0644);
    if (shm_fd < 0 && errno == ENOENT) {
        shm_created = true;
        shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0644);
    }
    if (shm_fd < 0) {
        perror("Can't open shared memory file");
        goto EXIT;
    }

    if (ftruncate(shm_fd, sizeof(datum)) < 0) { // !!!!!!!!!!!!!!!!!
        perror("Can't truncate shared memory object");
        goto EXIT;
    }

    shm_datum = mmap(NULL, sizeof(datum), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_datum == MAP_FAILED) {
        perror("Can't map shared object memory");
        goto EXIT;
    }

    if (shm_created) {
        shm_datum->time = 0;
        shm_datum->pid = 0;
        shm_datum->msg[0] = '\0';
    }

    while (1) {
        char time_buff[64];
        char buff[BUFF_SIZE];
        struct tm* tm_info;

        printf("Enter your message (%jd):", (intmax_t)getpid());
        if (fgets(buff, BUFF_SIZE - 1, stdin) == NULL) {
            puts("Exiting");
            break;
        }

        tm_info = localtime(&shm_datum->time);
        strftime(time_buff, 64, "%H:%M:%S", tm_info);
        if (shm_datum->pid != 0) {
            printf("Previous value was written by process with PID %jd at %s:\n%s",
                (intmax_t)shm_datum->pid, time_buff, shm_datum->msg);
        }
        shm_datum->pid = getpid();
        time(&shm_datum->time);
        strcpy(shm_datum->msg, buff);
    }

    exit_code = EXIT_SUCCESS;

EXIT:
    exit(exit_code);
}
