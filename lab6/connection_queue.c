#include "connection_queue.h"

int connection_queue_init(connection_queue *q, size_t max_connections) {
  q->count = 0;
  q->size = max_connections;
  q->items = malloc(sizeof(connection_queue_item) * max_connections);
  q->closed = false;
  pthread_cond_init(&q->empty_cvar, NULL);
  pthread_cond_init(&q->full_cvar, NULL);
  return pthread_mutex_init(&q->mutex, NULL);
}

void connection_queue_destroy(connection_queue *q) {
  if (!q->closed) {
    connection_queue_stop(q);
  }

  free(q->items);
  pthread_cond_destroy(&q->full_cvar);
  pthread_cond_destroy(&q->empty_cvar);
  pthread_mutex_destroy(&q->mutex);
}

static void queue_swap(connection_queue *q, size_t x, size_t y) {
  connection_queue_item tmp;
  connection_queue_item *a = &q->items[x];
  connection_queue_item *b = &q->items[y];

  tmp = *a;
  *a = *b;
  *b = tmp;
}

static void queue_sink(connection_queue *q, size_t pos) {
  if (pos == 0) {
    return;
  }
  size_t parent = pos / 2;
  connection_queue_item *parent_item = &q->items[parent];
  connection_queue_item *current_item = &q->items[pos];
  if (parent_item->priority > current_item->priority) {
    queue_swap(q, parent, pos);
    queue_sink(q, parent);
  }
}

static queue_result return_unlocking(connection_queue *q, queue_result res) {
  if (pthread_mutex_unlock(&q->mutex) < 0) {
    return QUEUE_ERR_MUTEX;
  } else {
    return res;
  }
}

queue_result connection_queue_add(connection_queue *q, queue_type item,
                                  size_t priority) {
  if (q->closed) {
    return QUEUE_CLOSED;
  }

  if (pthread_mutex_lock(&q->mutex) < 0) {
    return QUEUE_ERR_MUTEX;
  }

  while (q->count == q->size && !q->closed) {
    pthread_cond_wait(&q->full_cvar, &q->mutex);
  }

  if (q->closed) {
    return return_unlocking(q, QUEUE_CLOSED);
  }

  q->items[q->count].i = item;
  q->items[q->count].priority = priority;

  queue_sink(q, q->count);

  q->count += 1;
  if (q->count == 1) {
    pthread_cond_signal(&q->empty_cvar);
  }

  return return_unlocking(q, QUEUE_OK);
}

static void queue_surface(connection_queue *q, size_t pos) {
  size_t smallest = pos;
  size_t left = pos * 2;
  size_t right = pos * 2 + 1;
  size_t length = q->count;

  if (left < length && q->items[left].priority < q->items[smallest].priority) {
    smallest = left;
  }

  if (right < length &&
      q->items[right].priority < q->items[smallest].priority) {
    smallest = right;
  }

  if (smallest != pos) {
    queue_swap(q, smallest, pos);
    queue_surface(q, smallest);
  }
}

queue_result connection_queue_wait(connection_queue *q, queue_type *i) {
  if (q->closed) {
    return QUEUE_CLOSED;
  }

  if (pthread_mutex_lock(&q->mutex) < 0) {
    return QUEUE_ERR_MUTEX;
  }

  while (q->count == 0 && !q->closed) {
    pthread_cond_wait(&q->empty_cvar, &q->mutex);
  }

  if (q->closed) {
    return return_unlocking(q, QUEUE_CLOSED);
  }

  if (i != NULL) {
    *i = q->items[0].i;
  }

  q->count--;
  queue_swap(q, 0, q->count);
  queue_surface(q, 0);

  if (q->count == q->size - 1) {
    pthread_cond_signal(&q->full_cvar);
  }

  return return_unlocking(q, QUEUE_OK);
}

queue_result connection_queue_stop(connection_queue *q) {
  if (q->closed) {
    return QUEUE_ERR_CLOSED;
  }

  if (pthread_mutex_lock(&q->mutex) < 0) {
    return QUEUE_ERR_MUTEX;
  }

  q->closed = true;
  pthread_cond_broadcast(&q->full_cvar);
  pthread_cond_broadcast(&q->empty_cvar);

  return return_unlocking(q, QUEUE_OK);
}
