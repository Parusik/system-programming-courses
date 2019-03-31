#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <log.h>

#include "connection_queue.h"
#include "http_session.h"
#include "parser_context.h"
#include "worker_thread.h"

#define HTTP_BUFFER_SIZE 1024
#define CRLF "\r\n"

static const char *get_mime(const char *filename) {
  char *extension = strrchr(filename, '.');
  if (extension == NULL)
    return "application/text";
  extension += 1;

#define C(e, r)                                                                \
  if (strcmp(extension, e) == 0)                                               \
    return r;
  C("html", "text/html");
  C("css", "text/css");
  C("jpeg", "image/jpeg");
  C("jpg", "image/jpg");
  C("js", "application/javascript");
  C("png", "image/png");
  C("json", "application/json");
  C("pdf", "application/pdf");

  return "application/octet-stream";
}

static int receive_client(http_session *s, http_parser *parser,
                          http_parser_settings *settings, const char *root) {
  struct http_parser_url u;
  parser_context parser_context;
  struct stat stat_buff;
  char path[PATH_MAX];

  http_parser_init(parser, HTTP_REQUEST);
  http_parser_url_init(&u);
  parser_context_init(&parser_context, s, &u);
  parser->data = &parser_context;

  while (!parser_context.message_ended) {
    ssize_t recvd;
    size_t nparsed;
    char buffer[HTTP_BUFFER_SIZE];

    recvd = recv(s->fd, buffer, HTTP_BUFFER_SIZE, 0);
    if (recvd < 0) {
      log_error("Can't receive from client");
      return -1;
    } else if (recvd == 0) {
      log_warn("Client shutdown");
      return -1;
    } else {
      nparsed = http_parser_execute(parser, settings, buffer, recvd);
      if (nparsed != recvd) {
        log_warn("Can't parse");
        return -1;
      }
    }
  }

  if (parser->method != HTTP_GET) {
    log_warn("Wrong method type");
    return -1;
  }

  char *real_filename = s->filename[0] == '\0' ? "index.html" : s->filename;
  snprintf(path, PATH_MAX, "%s%s%s", root, s->path, real_filename);
  s->mime = get_mime(path);

  log_info("Requested Host: '%s', Path: '%s', File:'%s', Mime: '%s' Result "
           "file: '%s'",
           s->host, s->path, s->filename, s->mime, path);

  if (stat(path, &stat_buff) < 0) {
    if (errno == ENOENT) {
      goto HANDLE_404;
    }

    log_errno("Stat");
    return -1;
  }

  if (!S_ISLNK(stat_buff.st_mode) && !S_ISREG(stat_buff.st_mode)) {
    goto HANDLE_404;
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    log_error("Can't open requested file");
    return -1;
  }

  s->req_fd = fd;
  s->file_size = stat_buff.st_size;

  return 0;

HANDLE_404:
  s->file_size = 0;
  s->is_404 = 1;

  log_warn("Not found: %s", path);
  return 0;
}

int bind_socket(int port) {
  struct sockaddr_in in_addr;
  int server_socket;

  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket < 0) {
    return -1;
  }

  int opt = 1;
  if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) ==
      -1)
    log_errno("setsockopt");

  in_addr.sin_family = AF_INET;
  in_addr.sin_port = htons(port);
  in_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(server_socket, (struct sockaddr *)&in_addr, sizeof(in_addr)) < 0) {
    if (close(server_socket) < 0) {
      log_errno("Can't close server socket");
    }
    return -1;
  }

  return server_socket;
}

typedef struct {
  connection_queue *queue;
  const char *path;
} worker_context;

static void lock_log(void *udata, int lock) {
  pthread_mutex_t *m;

  m = udata;
  if (lock) {
    pthread_mutex_lock(m);
  } else {
    pthread_mutex_unlock(m);
  }
}

pthread_mutex_t *setup_log(FILE *f) {
  pthread_mutex_t *m;

  m = malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(m, NULL);

  log_set_udata(m);
  log_set_lock(lock_log);
  log_set_fp(f);

  return m;
}

void *worker_thread_wrapper(void *_context) {
  worker_context *c;

  c = _context;

  worker_thread(c->queue, c->path);

  return NULL;
}

void ignore_signal(int s) { (void)s; }

typedef struct {
  int port;
  const char *root;
  int threads;
  int queue;
  const char *log;
} opts;

int better_atoi(const char *input) {
  size_t l;
  int res;
  if (input == NULL)
    return -1;

  l = strlen(input);
  for (size_t i = 0; i < l; i++)
    if (!isdigit(input[i]))
      return -1;

  if (sscanf(input, "%d", &res) != 1)
    return -1;
  return res;
}

bool get_opts(opts *result, char *argv[], int argc) {
  int opt;

  result->port = -1;
  result->root = NULL;
  result->threads = -1;
  result->queue = -1;
  result->log = NULL;

  while ((opt = getopt(argc, argv, "p:d:t:q:l:")) != -1) {
    switch (opt) {
    case 'p':
      printf("p %s\n", optarg);
      result->port = better_atoi(optarg);
      break;
    case 'd':
      printf("d %s\n", optarg);
      result->root = optarg;
      break;
    case 't':
      printf("t %s\n", optarg);
      result->threads = better_atoi(optarg);
      printf("Threads: %d\n", result->threads);
      break;
    case 'q':
      printf("q %s\n", optarg);
      result->queue = better_atoi(optarg);
      break;
    case 'l':
      printf("l %s\n", optarg);
      result->log = optarg;
      break;
    default:
      return false;
    }
  }

  if (result->port < 1 || result->root == NULL || result->threads < 1 ||
      result->queue < 1 || result->log == NULL)
    return false;

  return true;
}

int main(int argc, char *argv[]) {
  struct sigaction sigact;
  worker_context worker_ctx;
  int exit_code, server_socket;
  connection_queue queue;
  pthread_t *ts;
  FILE *log;
  pthread_mutex_t *log_mutex;
  opts opt;

  exit_code = EXIT_FAILURE;

  if (!get_opts(&opt, argv, argc)) {
    fputs("Can't read options\n", stderr);
    fprintf(stderr, "Usage: %s -p port -d root -t threads -q queue -l log\n",
            argv[0]);
    goto EXIT;
  }

  if (daemon(0, 0) < 0) {
    perror("Can't daemonize");
    goto EXIT;
  }

  log = fopen(opt.log, "w");
  if (log == NULL) {
    goto EXIT;
  }
  log_mutex = setup_log(log);

  signal(SIGPIPE, SIG_IGN);

  sigact.sa_handler = ignore_signal;
  sigact.sa_flags = 0;
  sigemptyset(&sigact.sa_mask);
  if (sigaction(SIGINT, &sigact, NULL) < 0) {
    log_errno("Can't ignore SIGINT");
    goto CLOSE_LOG;
  }

  if (connection_queue_init(&queue, opt.queue) != QUEUE_OK) {
    log_errno("Can't create connection queue");
    goto CLOSE_LOG;
  }

  server_socket = bind_socket(opt.port);
  if (server_socket < 0) {
    log_errno("Can't open server socket");
    goto DESTROY_QUEUE;
  }

  if (listen(server_socket, 5) < 0) {
    log_errno("Can't listen server socket");
    goto CLOSE_SERVER;
  }

  worker_ctx.path = opt.root;
  worker_ctx.queue = &queue;
  ts = malloc(sizeof(pthread_t) * opt.threads);

  // threads init
  for (size_t i = 0; i < opt.threads; i++)
    pthread_create(&ts[i], NULL, worker_thread_wrapper, &worker_ctx);

  http_parser_settings settings;
  memset(&settings, 0, sizeof(settings));
  settings.on_message_complete = parser_on_message_complete;
  settings.on_header_field = parser_on_header_field;
  settings.on_header_value = parser_on_header_value;
  settings.on_url = parser_on_url;

  while (1) {
    http_parser *parser;
    http_session *session;
    int client_fd;

    parser = malloc(sizeof(http_parser));
    log_debug("Accepting");
    client_fd = accept(server_socket, NULL, NULL);
    if (client_fd < 0) {
      if (errno == EINTR) {
        free(parser);
        break;
      } else {
        log_errno("Can't accept client");
        continue;
      }
    }
    log_debug("Accepted");

    session = malloc(sizeof(http_session));
    http_session_init(session, client_fd);

/* 
  Parsing request
 */
    if (receive_client(session, parser, &settings, opt.root) < 0) {
      log_error("Error during receiving from client");
      if (close(session->fd) < 0) {
        log_errno("Can't close client socket");
      }
      free(session);
    } else {
      session->method = GET;
      // add to queue
      
      log_debug("Adding to queue %d", queue.count);
      connection_queue_add(&queue, session, session->file_size);
      log_debug("Added to queue %d", queue.count);
    }
  }

  exit_code = EXIT_SUCCESS;

  connection_queue_stop(&queue);
  for (size_t i = 0; i < opt.threads; i++) {
    pthread_join(ts[i], NULL);
  }
  free(ts);

CLOSE_SERVER:
  if (close(server_socket) < 0) {
    log_errno("Can't close server socket");
  }

DESTROY_QUEUE:
  for (size_t i = 0; i < queue.count; i++) {
    http_session *session;

    session = queue.items[i].i;
    if (!session->is_404 && close(session->req_fd) < 0) {
      log_errno("Can't close sent file");
    }
    free(session);
  }
  connection_queue_destroy(&queue);

CLOSE_LOG:
  pthread_mutex_destroy(log_mutex);
  free(log_mutex);
  fclose(log);

EXIT:
  exit(exit_code);
}
