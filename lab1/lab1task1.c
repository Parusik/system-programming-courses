#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFF_SIZE 512 //BUFSIZ

ssize_t write_buffer(int dest_fd, void *_buffer, size_t buffer_size)
{
    char *buffer;

    buffer = _buffer;

    for (size_t pos = 0; pos != buffer_size;)
    {
        ssize_t wrote_bytes;

        wrote_bytes = write(dest_fd, buffer + pos, buffer_size - pos);
        if (wrote_bytes < 0)
        {
            return -1;
        }

        pos += wrote_bytes;
    }

    return buffer_size;
}

ssize_t copy_files(int src_fd, int dest_fd, void *_buffer, size_t buffer_size)
{
    ssize_t read_bytes;
    size_t bytes_counter;
    char *buffer;

    buffer = _buffer;
    bytes_counter = 0;

    do
    {
        read_bytes = read(src_fd, buffer, buffer_size);
        if (read_bytes < 0)
        {
            return -1;
        }

        for (size_t i = 0; i < read_bytes; i++)
        {
            buffer[i] = tolower(buffer[i]);
        }

        if (write_buffer(dest_fd, buffer, read_bytes) < 0)
        {
            return -1;
        }

        bytes_counter += read_bytes;
    } while (read_bytes != 0);

    return bytes_counter;
}

int main(int argc, char *argv[])
{
    int exit_code;

    int in_fd, out_fd;

    ssize_t bytes_written;
    char buffer[BUFF_SIZE];

    exit_code = EXIT_FAILURE; //1

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s SRC DEST\n", argv[0]);
        goto EXIT;
    }

    in_fd = open(argv[1], O_RDONLY);
    if (in_fd < 0)
    {
        perror("Can't open input file");
        goto EXIT;
    }

    out_fd = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0644); //access level, overwrite
    if (out_fd < 0)
    {
        perror("Can't open output file");
        goto CLEANUP_IN_FD;
    }
    printf("%d %d", in_fd, out_fd);

    bytes_written = copy_files(in_fd, out_fd, buffer, BUFF_SIZE);
    if (bytes_written < 0)
    {
        perror("Can't copy file contents");
        goto CLEANUP_OUT_FD;
    }
    printf("Wrote %ld bytes\n", bytes_written);

    exit_code = EXIT_SUCCESS;

CLEANUP_OUT_FD:
    if (close(out_fd) != 0)
    {
        perror("Can't close output file");
        exit_code = EXIT_FAILURE;
    }

CLEANUP_IN_FD:
    if (close(in_fd) != 0)
    {
        perror("Can't close input file");
        exit_code = EXIT_FAILURE;
    }

EXIT:
    exit(exit_code);
}
