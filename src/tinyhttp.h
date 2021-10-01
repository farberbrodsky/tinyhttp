#include <unistd.h>
#ifndef _TINYHTTP_H
#define _TINYHTTP_H

#define BACKLOG 32
#define MAX_EPOLL_EVENTS 8

#define READ_BUF_SIZE 2048
#define WRITE_BUF_INITIAL_SIZE 2048

struct http_io_client;
typedef void (*http_io_client_new_handler)(struct http_io_client *c);
// Should not return, returns error code
int http_serve(int port_num, http_io_client_new_handler new_handler);

// Gets length of buffer, returns how much of it has been used
// data starts as NULL, and is a pointer to a void *. It is used for state.
// You are responsible for allocating/freeing *data.
typedef size_t (*http_io_client_read_handler)(struct http_io_client *c, const char *buf, size_t count, void **data);

struct http_io_client {
    void *custom_data;

    int fd;
    char read_buf[READ_BUF_SIZE];
    unsigned int read_buf_start;
    unsigned int read_buf_end;

    http_io_client_read_handler rd_handler;
    void *rd_handler_data;

    char *write_buf;
    unsigned int write_buf_start;
    unsigned int write_buf_end;
    unsigned int write_buf_size;
};

void http_client_write(struct http_io_client *c, const char *buf, size_t count);

// Every http io client has one read handler
void http_io_client_set_read_handler(struct http_io_client *c, http_io_client_read_handler rd_handler);

#endif
