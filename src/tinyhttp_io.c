#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "tinyhttp_io.h"
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>

static struct http_io_global_struct {
    int epoll_fd;
    int server_fd;
    http_io_client_new_handler new_handler;
    http_io_client_error_handler err_handler;
} http_io_global;


// indexes in this array are based on file descriptors
static struct http_io_client **http_io_clients = NULL;
static size_t http_clients_max_fd = 0;

static void alloc_http_client(int fd) {
    if (fd > http_clients_max_fd) {
        if (http_io_clients != NULL) 
            http_io_clients = realloc(http_io_clients, (fd + 1) * sizeof(struct http_io_client *));
        else
            http_io_clients = calloc(sizeof(struct http_io_client *), fd + 1);
    }

    for (int i = http_clients_max_fd + 1; i < fd; i++) {
        http_io_clients[i] = NULL;
    }

    http_io_clients[fd] = calloc(1, sizeof(struct http_io_client));
    http_io_clients[fd]->fd = fd;
    http_io_clients[fd]->write_buf = malloc(WRITE_BUF_INITIAL_SIZE);
    http_io_clients[fd]->write_buf_size = WRITE_BUF_INITIAL_SIZE;
    http_clients_max_fd = fd;
}

static void free_http_io_client(int fd) {
    struct http_io_client *c = http_io_clients[fd];
    if (c == NULL) return;

    free(c->write_buf);
    free(c);
    http_io_clients[fd] = NULL;
}

// count=0 is for writing as much as possible
void http_io_client_write(struct http_io_client *c, const char *buf, size_t count) {
    size_t r_count = count;  // remaining count
    if (r_count > 0) {
        // add some of buf to the write buffer if there is already space
        size_t copy_amount = c->write_buf_size - c->write_buf_end;
        if (copy_amount > r_count) copy_amount = r_count;

        memcpy(c->write_buf + c->write_buf_end, buf, copy_amount);
        c->write_buf_end += copy_amount;
        buf += copy_amount;
        r_count -= copy_amount;
    }

    // try to write as much of the existing buffer as possible
    errno = 0;
    int written;
    
    if (count == 0 || (c->write_buf_end - c->write_buf_start) > 1024) {  // to reduce the amount of syscalls
        while (c->write_buf_end != c->write_buf_start &&
              (written = write(c->fd, c->write_buf + c->write_buf_start, c->write_buf_end - c->write_buf_start)) > 0)
            c->write_buf_start += written;
    }

    if (r_count == 0) return;

    if (errno != EAGAIN && c->write_buf_end == c->write_buf_start) {
        // try to write some more of the new buffer too
        while (count > 0 && (written = write(c->fd, buf, count)) > 0) {
            buf += written;
            count -= written;
        }
    }

    // what remains of buf must be added to c->write_buf
    size_t needed_write_buf_size = c->write_buf_end - c->write_buf_start + r_count;
    if (needed_write_buf_size > c->write_buf_size) {
        // must grow, grow to closest power of two
        while (c->write_buf_size < needed_write_buf_size)
            c->write_buf_size <<= 1;
        
        char *new_write_buf = malloc(c->write_buf_size);
        memcpy(new_write_buf, c->write_buf + c->write_buf_start, c->write_buf_end - c->write_buf_start);
        memcpy(new_write_buf + c->write_buf_end - c->write_buf_start, buf, r_count);

        free(c->write_buf);
        c->write_buf = new_write_buf;
        c->write_buf_start = 0;
        c->write_buf_end = needed_write_buf_size;
    } else {
        // we can fit it! (if we try hard enough)
        if (r_count <= (c->write_buf_size - c->write_buf_end)) {
            // we can fit it easily without moving memory
            memcpy(c->write_buf + c->write_buf_end, buf, r_count);
        } else {
            // we must move memory
            memmove(c->write_buf, c->write_buf + c->write_buf_start, c->write_buf_end - c->write_buf_start);
            c->write_buf_end -= c->write_buf_start;
            c->write_buf_start = 0;
            memcpy(c->write_buf + c->write_buf_end, buf, r_count);
            c->write_buf_end += r_count;
        }
    }
}

void http_client_close(struct http_io_client *c) {
    c->should_be_removed = true;
}

void http_client_close_on_error(struct http_io_client *c, int err) {
    http_io_global.err_handler(c, err);
    http_client_close(c);
}

static void http_io_respond();
int http_serve(int port_num, http_io_client_new_handler new_handler, http_io_client_error_handler err_handler) {
    http_io_global.new_handler = new_handler;
    http_io_global.err_handler = err_handler;

    struct addrinfo hints, *addrinfo_result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    // convert port_num to string
    char port_str[6];
    snprintf(port_str, 6, "%d", port_num);

    if (getaddrinfo(NULL, port_str, &hints, &addrinfo_result) != 0) {
        return -1;
    }

    int server_fd = socket(addrinfo_result->ai_family, addrinfo_result->ai_socktype | SOCK_NONBLOCK, addrinfo_result->ai_protocol);
    if (server_fd == -1) {
        return -2;
    }
    if (bind(server_fd, addrinfo_result->ai_addr, addrinfo_result->ai_addrlen) != 0) {
        close(server_fd);
        return -3;
    }
    freeaddrinfo(addrinfo_result);

    if (listen(server_fd, BACKLOG) != 0) {
        close(server_fd);
        return -4;
    }

    // start epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        close(server_fd);
        return -5;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        close(server_fd);
        return -5;
    }

    http_io_global.epoll_fd = epoll_fd;
    http_io_global.server_fd = server_fd;
    while (true) http_io_respond();

    fprintf(stderr, "Something failed!\n");
    return 0;
}

static void http_io_respond() {
    int epoll_fd = http_io_global.epoll_fd;
    int server_fd = http_io_global.server_fd;

    struct epoll_event ev, events[MAX_EPOLL_EVENTS];
    int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);

    if (nfds == -1) {
        perror("couldn't wait for epoll");
        close(server_fd);
        close(epoll_fd);
        exit(1);
    }

    for (int i = 0; i < nfds; i++) {
        if (events[i].data.fd == server_fd) {
            struct sockaddr_storage peer_address;
            socklen_t peer_address_len = sizeof(peer_address);
            int peer_fd;
            while ((peer_fd = accept4(server_fd, (struct sockaddr *)&peer_address, &peer_address_len, SOCK_NONBLOCK)) != -1) {
                alloc_http_client(peer_fd);

                ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLET;
                ev.data.fd = peer_fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, peer_fd, &ev) != 0) {
                    perror("couldn't add to epoll");
                    close(server_fd);
                    close(epoll_fd);
                    close(peer_fd);
                    exit(1);
                }

                if (http_io_global.new_handler == NULL) {
                    fprintf(stderr, "NO HANDLER: Connection: %d\n", peer_fd);
                } else {
                    http_io_global.new_handler(http_io_clients[peer_fd]);
                }
            }
        } else {
            int peer_fd = events[i].data.fd;
            struct http_io_client *c = http_io_clients[peer_fd];
            if (c == NULL) continue;

            if (!c->should_be_removed && events[i].events & (EPOLLIN | EPOLLHUP)) {
                char buf[READ_BUF_SIZE];
                ssize_t read_count = 0;

                if (c->rd_handler == NULL) {
                    fputs("NO READ HANDLER!!!", stderr);
                }

                char *buf_p = buf;
                while (!c->should_be_removed && 
                        (read_count > 0 || (buf_p = buf, read_count = read(peer_fd, buf, READ_BUF_SIZE)) > 0)) {
                    size_t cnt = c->rd_handler(c, buf_p, read_count, c->rd_handler_arg, &c->rd_handler_data);
                    read_count -= cnt;
                    buf_p += cnt;
                }
                if (events[i].events & EPOLLHUP || read_count == 0 || (read_count == -1 && errno != EAGAIN)) {
                    c->should_be_removed = true;  // nothing to read anymore
                }
            }

http_respond_writeout:
            // if possible, write stuff out from the buffer
            if (http_io_clients[peer_fd] != NULL && events[i].events & EPOLLOUT) {
                // printf("Ready for out %d!\n", peer_fd);
                http_io_client_write(c, NULL, 0);
            }

            // remove c only if the write buf is done or if c closed already
            if (events[i].events & EPOLLHUP ||
                    (c->should_be_removed && c->write_buf_start == c->write_buf_end)) {
                if (c->free_handler != NULL) {
                    c->free_handler(c);
                    c->free_handler = NULL;
                    // free handler may have written stuff
                    if (!(events[i].events & EPOLLHUP)
                            && c->write_buf_start != c->write_buf_end) {
                        goto http_respond_writeout;
                    }
                }

                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, peer_fd, NULL) != 0) {
                    perror("couldn't remove");
                    exit(1);
                }

                close(peer_fd);
                free_http_io_client(peer_fd);
            }
        }
    }
}

void http_io_client_set_read_handler(struct http_io_client *c, http_io_client_read_handler rd_handler, void *arg) {
    c->rd_handler = rd_handler;
    c->rd_handler_data = NULL;
    c->rd_handler_arg = arg;
}

void http_io_client_set_free_handler(struct http_io_client *c, http_io_client_free_handler free_handler) {
    c->free_handler = free_handler;
}

#endif
