#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

#define BUFF_SIZE 256
int log_fd;

void handle_signal(int signo, siginfo_t* si, void* _ucontext)
{
    int msg_len;
    char buff[BUFF_SIZE];

    msg_len = snprintf(buff, BUFF_SIZE,
        "Got signal: %s\n"
        "Sender PID: %jd\n" // for int max
        "Sender UID: %jd\n",
        strsignal(signo),
        (intmax_t)si->si_pid,
        (intmax_t)si->si_uid);

    if (write_buffer(log_fd, buff, msg_len) < 0) {
        perror("Can't write signal info to buffer");
    }
}

int main()
{
    int exit_code;
    char buff[BUFF_SIZE];
    int msg_len;
    struct sigaction new_action, old_action;

    exit_code = EXIT_FAILURE;

    log_fd = open("/tmp/daemon.log", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (log_fd < 0) {
        perror("Can't open log file");
        goto EXIT;
    }

    msg_len = snprintf(buff, BUFF_SIZE, "Launched daemon with PID: %jd\n", (intmax_t)getpid());
    if (write_buffer(log_fd, buff, msg_len) < 0) {
        perror("Can't write to log file");
        goto CLOSE_LOG;
    }

    sigemptyset(&new_action.sa_mask); //blok  signals in handler run time 
    new_action.sa_flags = SA_SIGINFO;
    new_action.sa_sigaction = handle_signal;

    if (sigaction(SIGHUP, &new_action, &old_action) < 0) { //old_action may be null
        perror("Can't set signal handler");
        goto CLOSE_LOG;
    }

    while (1) {
        time_t t;
        struct tm* timeinfo;

        time(&t);
        timeinfo = localtime(&t);

        msg_len = snprintf(buff, BUFF_SIZE, "Daemon working: %d/%d/%d %02d:%02d:%02d\n",
            timeinfo->tm_mday,
            timeinfo->tm_mon + 1,
            timeinfo->tm_year + 1900,
            timeinfo->tm_hour,
            timeinfo->tm_min,
            timeinfo->tm_sec);

        if (write_buffer(log_fd, buff, msg_len) < 0) {
            perror("Can't write time to log file");
            goto CLOSE_LOG;
        }
        sleep(5);
    }

    exit_code = EXIT_SUCCESS;

CLOSE_LOG:
    if (close(log_fd) < 0) {
        perror("Can't close log");
    }

EXIT:
    exit(exit_code);
}
