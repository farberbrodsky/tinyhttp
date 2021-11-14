#ifndef _TINYHTTP_IO_H
#define _TINYHTTP_IO_H
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include "tinyhttp_client_struct.h"

#define BACKLOG 32
#define AIO_NR_EVENTS 1024
#define MAX_EPOLL_EVENTS 8

#define READ_BUF_SIZE 2048
#define WRITE_BUF_INITIAL_SIZE 2048

struct http_io_client;
typedef void (*http_io_client_new_handler)(struct http_io_client *c);
typedef void (*http_io_client_error_handler)(struct http_io_client *c, int err_code);
// Should not return, returns error code
int http_serve(int port_num, http_io_client_new_handler new_handler, http_io_client_error_handler err_handler);

// Gets length of buffer, returns how much of it has been used
// data starts as NULL, and is a pointer to a void *. It is used for state.
// arg can be passed when setting a read handler,
// and is given as an argument every time.
// You are responsible for allocating/freeing *data and freeing arg.
typedef size_t (*http_io_client_read_handler)(struct http_io_client *c, const char *buf, size_t count, void *arg, struct http_io_client_extra *extra);
typedef void (*http_io_client_free_handler)(struct http_io_client *c);

struct http_io_client {
    struct http_client_data client_data;
    int fd;

    http_io_client_read_handler rd_handler;
    struct http_io_client_extra rd_handler_data;
    void *rd_handler_arg;

    http_io_client_free_handler free_handler;
    bool should_be_removed;  // set when a client caused an error and we want to finish writing

    char *write_buf;
    unsigned int write_buf_start;
    unsigned int write_buf_end;
    unsigned int write_buf_size;
    bool out_ready;  // use this instead of checking by EPOLLOUT every time because it can be saved across waits

    struct http_io_client *__is_an_event_for;  // if this file descriptor is just a listener for another client
    int *__fd_list;  // list of fd listeners: first item is the length of the list, then the file descriptors
};

void http_io_client_write(struct http_io_client *c, const char *buf, size_t count);
void http_client_close(struct http_io_client *c);
void http_client_close_on_error(struct http_io_client *c, int err);

// Every http io client has one read handler
void http_io_client_set_read_handler(struct http_io_client *c, http_io_client_read_handler rd_handler, void *arg);
// Also call with buf=NULL, count=0
void http_io_client_set_read_handler_immediate(struct http_io_client *c, http_io_client_read_handler rd_handler, void *arg);
void http_io_client_set_free_handler(struct http_io_client *c, http_io_client_free_handler free_handler);

#define BUF_OTHER (void *)1
// Listen to events from an extra file descriptor, useful for e.g. serving files and asynchronously reading them.
// In those events, extra->event is set and res, res2 are from the io_event. count and buf are 0.
void http_io_add_fd(struct http_io_client *c, int fd, uint32_t listen_events);
// Stop listening to an fd. It checks that you added the file descriptor, and does nothing if you hadn't. Completely optional, it is called automatically when the client is closed.
void http_io_remove_fd(struct http_io_client *c, int fd);
// Submit an iocb, you will get an event if the file descriptor is in your list
void http_io_submit_op(struct iocb *iocbp);

#endif
