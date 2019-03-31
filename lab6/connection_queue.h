#pragma once

#include "http_session.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

typedef enum {
  QUEUE_OK,
  QUEUE_CLOSED,
  QUEUE_ERR_MUTEX,
  QUEUE_ERR_CLOSED
} queue_result;

typedef http_session *queue_type;

typedef struct {
  queue_type i;
  size_t priority;
} connection_queue_item;

typedef struct {
  size_t size;
  size_t count;
  bool closed;
  connection_queue_item *items;
  pthread_mutex_t mutex;
  pthread_cond_t full_cvar;
  pthread_cond_t empty_cvar;
} connection_queue;

int connection_queue_init(connection_queue *q, size_t max_connections);
void connection_queue_destroy(connection_queue *q);
queue_result connection_queue_add(connection_queue *q, queue_type item,
                                  size_t priority);
queue_result connection_queue_wait(connection_queue *q, queue_type *i);
queue_result connection_queue_stop(connection_queue *q);
