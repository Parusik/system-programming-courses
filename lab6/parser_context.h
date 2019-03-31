#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define PARSER_BUFFER_SIZE 1024

#include "http_session.h"
#include <http_parser.h>

typedef enum {
  PARSING_URL = 1,
  PARSING_HEADER_NAME = 2,
  PARSING_HOST_VALUE = 3,
  PARSING_UNUSED_HEADER = 4
} parsing_state;

typedef struct {
  char buffer[PARSER_BUFFER_SIZE];
  size_t buffer_pos;
  parsing_state state;
  bool message_ended;
  struct http_parser_url *u;
  http_session *s;
} parser_context;

void parser_context_init(parser_context *c, http_session *s,
                         struct http_parser_url *u);

int parser_on_message_begin(http_parser *_);
int parser_on_headers_complete(http_parser *_);
int parser_on_message_complete(http_parser *p);
int parser_on_url(http_parser *_, const char *at, size_t length);
int parser_on_header_field(http_parser *p, const char *at, size_t length);
int parser_on_header_value(http_parser *_, const char *at, size_t length);
int parser_on_body(http_parser *_, const char *at, size_t length);
