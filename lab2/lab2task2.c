#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    intmax_t pid, sid;
    FILE* log_file;
    int parent_fds[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };

    log_file = fopen("/tmp/lab2.log", "w");
    if (!log_file) {
        perror("Can't open log");
        exit(EXIT_FAILURE);
    }
/* 
    DAEMONIZATION
 */

    // Fork
    pid = fork();
    if (pid < 0) {
        perror("Can't fork");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) { // Is parent
        if (fputs("Daemon was started\n", log_file) < 0) {
            perror("Can't write to file");
        }
        if (fclose(log_file) != 0) {
            perror("Can't close log file");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    // SetSid
    if (setsid() < 0) {
        perror("Can't create session"); //create new session
        exit(EXIT_FAILURE);
    }

    // ChDir
    if (chdir("/") < 0) {
        perror("Can't change directory to root");
        exit(EXIT_FAILURE);
    }

    // Close all parent's FDs
    for (int i = 0; i < 3; i++) {
        if (close(parent_fds[i]) < 0) {
            perror("Can't close parent FD");
            exit(EXIT_FAILURE);
        }
    }
    if (fclose(log_file) < 0) {
        perror("Can't close log file");
        exit(EXIT_FAILURE);
    }

/* 
   END
 */

    // Open standard FDS
    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+");

    pid = getpid();
    sid = getsid(0);

    log_file = fopen("/tmp/lab2.log", "a");
    if (!log_file) {
        exit(EXIT_FAILURE);
    }
    
    // process params 
    fprintf(log_file, "PID=%jd SID=%jd\n", pid, sid);
    fclose(log_file);

    while (1)
        sleep(1);
}
