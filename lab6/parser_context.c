#include "parser_context.h"

#include <log.h>
#include <string.h>

static int save_url(parser_context *ctx) {
  http_session *s;
  const char *buffer;
  struct http_parser_url *u;

  if (http_parser_parse_url(ctx->buffer, ctx->buffer_pos, 0, ctx->u) < 0) {
    return -1;
  }

  s = ctx->s;
  u = ctx->u;
  buffer = ctx->buffer;

  if ((u->field_set & (1 << UF_PATH)) == 0) {
    log_error("Invalid URL");
    return -1;
  }

  size_t len = u->field_data[UF_PATH].len;
  const char *url_start = buffer + u->field_data[UF_PATH].off;
  const char *url_end = url_start + len;

  const char *path_start = url_start + 1;
  const char *file_start = NULL;
  for (int i = len - 1; i >= 0; i--) {
    if (url_start[i] == '/') {
      file_start = url_start + i + 1;
      break;
    }
  }

  if (file_start == NULL) {
    log_error("No file specified");
    return -1;
  }

  size_t path_len = file_start - path_start;
  size_t filename_len = url_end - file_start;
  if (path_len >= MAX_PATH_LENGTH - 1 ||
      filename_len >= MAX_FILENAME_LENGTH - 1) {
    log_error("Too long path");
    return -1;
  }
  memcpy(s->path, path_start, path_len);
  memcpy(s->filename, file_start, filename_len);
  s->path[path_len] = '\0';
  s->filename[filename_len] = '\0';

  return 0;
}

static int save_host(http_session *s, const char *buffer, size_t len) {
  if (len >= MAX_HOST_LENGTH - 1) {
    return -1;
  }

  memcpy(s->host, buffer, len);
  s->host[len] = '\0';

  return 0;
}

void parser_context_init(parser_context *c, http_session *s,
                         struct http_parser_url *u) {
  c->buffer_pos = 0;
  c->state = PARSING_URL;
  c->message_ended = false;
  c->s = s;
  c->u = u;
}

int parser_on_message_complete(http_parser *p) {
  parser_context *ctx = p->data;
  ctx->message_ended = true;

  if (ctx->state == PARSING_URL) {
    if (save_url(ctx) < 0) {
      log_error("Can't save URL");
      return -1;
    }
  }

  if (ctx->state == PARSING_HOST_VALUE) {
    if (save_host(ctx->s, ctx->buffer, ctx->buffer_pos) < 0) {
      log_error("Too big host value");
      return -1;
    }
  }

  return 0;
}

static int bwrite(char *buffer, size_t *buffer_pos, size_t buffer_len,
                  const char *at, size_t length) {
  size_t new_pos = *buffer_pos + length;

  if (new_pos >= buffer_len) {
    return -1;
  }

  for (size_t i = *buffer_pos; i < new_pos; i++)
    buffer[i] = *at++;

  *buffer_pos = new_pos;

  return 0;
}

int parser_on_url(http_parser *p, const char *at, size_t length) {
  parser_context *ctx = p->data;

  if (bwrite(ctx->buffer, &ctx->buffer_pos, PARSER_BUFFER_SIZE, at, length) <
      0) {
    log_error("Too big URL");
    return -1;
  }

  return 0;
}

int parser_on_header_field(http_parser *p, const char *at, size_t length) {
  parser_context *ctx = p->data;

  if (ctx->state == PARSING_URL) {
    ctx->state = PARSING_HEADER_NAME;

    if (save_url(ctx) < 0) {
      return -1;
    }
    ctx->buffer_pos = 0;
  }

  if (ctx->state == PARSING_UNUSED_HEADER) {
    ctx->buffer_pos = 0;
    ctx->state = PARSING_HEADER_NAME;
  }

  if (ctx->state == PARSING_HEADER_NAME) {
    if (bwrite(ctx->buffer, &ctx->buffer_pos, PARSER_BUFFER_SIZE, at, length) <
        0) {
      log_error("Too big header name");
      return -1;
    }
  }

  if (ctx->state == PARSING_HOST_VALUE) {
    ctx->state = PARSING_HEADER_NAME;
    if (save_host(ctx->s, ctx->buffer, ctx->buffer_pos) < 0) {
      log_error("Too big host value");
      return -1;
    }
    ctx->buffer_pos = 0;

    if (bwrite(ctx->buffer, &ctx->buffer_pos, PARSER_BUFFER_SIZE, at, length) <
        0) {
      log_error("Too big header name");
      return -1;
    }
  }

  return 0;
}

int parser_on_header_value(http_parser *p, const char *at, size_t length) {
  parser_context *ctx = p->data;

  if (ctx->state == PARSING_HEADER_NAME) {
    if (strncmp(ctx->buffer, "Host", ctx->buffer_pos) == 0) {
      ctx->state = PARSING_HOST_VALUE;
      ctx->buffer_pos = 0;
    } else {
      ctx->state = PARSING_UNUSED_HEADER;
      return 0;
    }
  }

  if (ctx->state == PARSING_HOST_VALUE) {
    if (bwrite(ctx->buffer, &ctx->buffer_pos, PARSER_BUFFER_SIZE, at, length) <
        0) {
      log_error("Too big host value");
      return -1;
    }
  }

  return 0;
}
