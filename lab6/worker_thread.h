#pragma once

#include "connection_queue.h"

void worker_thread(connection_queue *queue, const char *root);
