gcc -I rxi-log/ -I http-parser-2.8.1/ rxi-log/log.c http-parser-2.8.1/http_parser.c connection_queue.c http_session.c parser_context.c worker_thread.c main.c -lpthread
