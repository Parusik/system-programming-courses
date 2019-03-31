#include "worker_thread.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <log.h>

#include "parser_context.h"

#define HTTP_BUFFER_SIZE 1024
#define CRLF "\r\n"

ssize_t write_buffer(int fd, const void *_buffer, size_t size) {
  size_t bytes_counter;
  const char *buffer = _buffer;
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

static int send_404(int fd) {
  char buff[1024];
  char tm_buff[100];
  time_t t;
  struct tm tmp;

  t = time(NULL);
  localtime_r(&t, &tmp);
  strftime(tm_buff, 100, "%a, %d %b %Y %H:%M:%S %Z", &tmp);
  snprintf(buff, 1024,
           "HTTP/1.1 404 Not Found" CRLF "Content-Length: 9" CRLF
           "Connection: close" CRLF "Date: %s" CRLF CRLF "Not Found",
           tm_buff);

  return send(fd, buff, strlen(buff), 0);
}

static int reply_client(http_session *s) {
  char buffer[HTTP_BUFFER_SIZE];
  int exit_code, msg_len;
  char tm_buff[100];
  time_t t;
  struct tm tmp;

  exit_code = -1;

  t = time(NULL);
  localtime_r(&t, &tmp);
  strftime(tm_buff, 100, "%a, %d %b %Y %H:%M:%S %Z", &tmp);

  if (s->is_404) {
    exit_code = send_404(s->fd);
    goto CLOSE_CLIENT;
  }

  msg_len = snprintf(buffer, HTTP_BUFFER_SIZE,
                     "HTTP/1.1 200 OK" CRLF "Content-Length: %zd" CRLF
                     "Connection: close" CRLF "Content-Type: %s" CRLF
                     "Date: %s" CRLF CRLF,
                     s->file_size, s->mime, tm_buff);

  if (send(s->fd, buffer, msg_len, 0) < 0) {
    log_errno("Error during sending data to client");
    goto CLOSE_CLIENT;
  }

  size_t total_read = 0;
  while (1) {
    ssize_t r;
    char buffer[1024];
    r = read(s->req_fd, buffer, 1024);
    if (r < 0) {
      log_errno("Can't read from client");
      goto CLOSE_CLIENT;
    }

    total_read += r;

    if (write_buffer(s->fd, buffer, r) < 0) {
      log_errno("Can't write to client");
      goto CLOSE_CLIENT;
    }

    if (total_read == s->file_size)
      break;
  }

  exit_code = 0;

CLOSE_CLIENT:
  if (close(s->fd) < 0) {
    log_errno("Can't close client socket");
  }

  return exit_code;
}

void worker_thread(connection_queue *queue, const char *root) {

  http_session *session;
  queue_result res;

  while (1) {
    log_debug("Waiting for tasks %d", queue->count);
    res = connection_queue_wait(queue, &session);
    if (res != QUEUE_OK)
      break;
    log_debug("Got task %d", queue->count);

    if (reply_client(session) < 0) {
      log_errno("Error during sending to client");
    }
    if (!session->is_404 && close(session->req_fd) < 0) {
      log_errno("Can't close sent file");
    }
    free(session);
  }
  if (res == QUEUE_CLOSED) {
    log_info("Stopping worker");
  } else {
    log_error("Queue error");
  }
}
