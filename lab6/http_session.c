#include "http_session.h"

void http_session_init(http_session *s, int fd) {
  s->fd = fd;
  s->method = UNKNOWN;

  s->host[0] = 0;
  s->path[0] = 0;
  s->filename[0] = 0;

  gettimeofday(&s->request_time, NULL);

  s->is_404 = 0;
}
