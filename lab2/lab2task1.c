#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    intmax_t process_id, session_id, group_id, user_id;
} process_info;

void print_process_info(const char* name, const process_info* proc)
{
    printf(
        "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n"
        "[%s] Process ID(PID):         %jd\n"
        "[%s] Process user ID(GID):    %jd\n"
        "[%s] Process group ID(GID):   %jd\n"
        "[%s] Process session ID(SID): %jd\n"
        "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        name, proc->process_id, name, proc->user_id, name, proc->group_id, name,
        proc->session_id);
}

int main(void)
{
    process_info proc_info;
    intmax_t fork_pid;

    proc_info.process_id = getpid();
    proc_info.user_id = getuid();
    proc_info.group_id = getgid();
    if ((proc_info.session_id = getsid(0)) < 0) { //session  ID is returned
        perror("getsid() error");
        exit(EXIT_FAILURE);
    }

    print_process_info("pre-fork", &proc_info);

    fork_pid = fork();
    if (fork_pid < 0) {
        perror("Failed to fork()");
        exit(EXIT_FAILURE);
    }

    if (fork_pid == 0) { // In child
        proc_info.process_id = getpid();
        for (int i = 0; i < 10; i++) {
            print_process_info("child", &proc_info);
        }
        exit(EXIT_SUCCESS);
    }

    for (int i = 0; i < 10; i++) {
        print_process_info("parent", &proc_info);
    }

    if (wait(NULL) < 0) { // returns exit status from child process
        perror("wait() failed in parent");
        exit(EXIT_FAILURE);
    }

    puts("Parent and child have exited");
    exit(EXIT_SUCCESS);
}
