#pragma once

#include <http_parser.h>
#include <sys/time.h>

#define MAX_PATH_LENGTH 200
#define MAX_FILENAME_LENGTH 200
#define MAX_HOST_LENGTH 100

typedef enum { GET, POST, PUT, DELETE, UNKNOWN } request_method;

typedef struct {
  int fd;
  request_method method;

  char host[MAX_HOST_LENGTH];
  char path[MAX_PATH_LENGTH];
  char filename[MAX_FILENAME_LENGTH];
  const char *mime;

  struct timeval request_time;
  struct timezone request_timezone;

  int is_404;
  size_t req_fd;
  size_t file_size;
} http_session;

void http_session_init(http_session *s, int fd);
