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

// allocate space for this to be a valid index
static void make_space_for_http_client(int fd) {
    if (fd > http_clients_max_fd) {
        if (http_io_clients != NULL) 
            http_io_clients = realloc(http_io_clients, (fd + 1) * sizeof(struct http_io_client *));
        else
            http_io_clients = calloc(sizeof(struct http_io_client *), fd + 1);

        http_clients_max_fd = fd;
    }

    for (int i = http_clients_max_fd + 1; i < fd; i++) {
        http_io_clients[i] = NULL;
    }
}

static void alloc_http_client(int fd) {
    make_space_for_http_client(fd);
    http_io_clients[fd] = calloc(1, sizeof(struct http_io_client));
    http_io_clients[fd]->fd = fd;
    http_io_clients[fd]->write_buf = malloc(WRITE_BUF_INITIAL_SIZE);
    http_io_clients[fd]->write_buf_size = WRITE_BUF_INITIAL_SIZE;
}

static void free_http_io_client(int fd) {
    struct http_io_client *c = http_io_clients[fd];
    if (c == NULL) return;

    // remove all fd listeners
    while (c->__fd_list != NULL) {
        http_io_remove_fd_listener(c, c->__fd_list[1]);
    }

    free(c->write_buf);
    free(c);

    http_io_clients[fd] = NULL;
}

void http_io_add_fd_listener(struct http_io_client *c, int fd, uint32_t listen_events) {
    // add the fd to http_io_clients, with __is_an_event_for
    make_space_for_http_client(fd);
    http_io_clients[fd] = calloc(1, sizeof(struct http_io_client));
    http_io_clients[fd]->__is_an_event_for = c;

    // add to c's list, the length is c->__fd_list[0]
    // this list is useful because we want to free them at some point
    if (c->__fd_list != NULL) {
        // make space for another entry
        c->__fd_list = realloc(c->__fd_list, sizeof(int) * (c->__fd_list[0] + 2));
        ++(c->__fd_list[0]);
    } else {
        // create a new __fd_list
        c->__fd_list = malloc(sizeof(int) * 2);
        c->__fd_list[0] = 1;
    }
    c->__fd_list[c->__fd_list[0]] = fd;  // append to c->__fd_list

    struct epoll_event ev;
    ev.events = listen_events; // | EPOLLET
    ev.data.fd = fd;
    if (epoll_ctl(http_io_global.epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        perror("Couldn't add fd listener");
    }
}

void http_io_remove_fd_listener(struct http_io_client *c, int fd) {
    if (c->__fd_list == NULL) return;
    // find index in __fd_list
    int len = c->__fd_list[0];
    int i = 1;

    for (; i <= len; i++) {
        if (c->__fd_list[i] == fd) {
            goto found_index;
        }
    }
    return;  // not found, not really a registered fd

found_index:
    // remove index from __fd_list
    if (c->__fd_list[0] <= 1) {
        // can completely free the list
        free(c->__fd_list);
        c->__fd_list = NULL;
    } else {
        // move the last item to this index to delete
        c->__fd_list[i] = c->__fd_list[c->__fd_list[0]];
        c->__fd_list = realloc(c->__fd_list, sizeof(int) * ((c->__fd_list[0])--));
    }

    // remove the fd from epoll and from our list
    free(http_io_clients[fd]);
    http_io_clients[fd] = NULL;
    epoll_ctl(http_io_global.epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

// used by http_io_client_write, it writes as much as possible
static void http_io_client_try_flush(struct http_io_client *c) {
    if (!c->out_ready || c->write_buf_start == c->write_buf_end) return;

    int written;
    while (c->write_buf_end != c->write_buf_start &&
          (written = write(c->fd, c->write_buf + c->write_buf_start, c->write_buf_end - c->write_buf_start)) > 0) {
        c->write_buf_start += written;
    }
    if (written == -1 && errno == EAGAIN) c->out_ready = false;
}

void http_io_client_write(struct http_io_client *c, const char *buf, size_t count) {
    // LOGGING
    if (buf != NULL) {
        fflush(stdout);
        printf("writing to %d:", c->fd);
        fflush(stdout);
        write(1, buf, count);
        write(1, "\n", 1);
        fflush(stdout);
    }
    // END LOGGING

    if (count > 0) {
        // add some of buf to the write buffer if there is already space
        size_t copy_amount = c->write_buf_size - c->write_buf_end;
        if (copy_amount > count) copy_amount = count;

        memcpy(c->write_buf + c->write_buf_end, buf, copy_amount);
        c->write_buf_end += copy_amount;
        buf += copy_amount;
        count -= copy_amount;
    }

    // try to write as much of the existing buffer as possible
    http_io_client_try_flush(c);

    if (c->out_ready && c->write_buf_end == c->write_buf_start) {
        // try to write some more of the new buffer too directly
        int written;
        while (count > 0 && (written = write(c->fd, buf, count)) > 0) {
            buf += written;
            count -= written;
        }
        if (written == -1 && errno == EAGAIN) c->out_ready = false;
    }

    // what remains of buf must be added to c->write_buf
    size_t needed_write_buf_size = c->write_buf_end - c->write_buf_start + count;
    if (needed_write_buf_size > c->write_buf_size) {
        // must grow, grow to closest power of two
        while (c->write_buf_size < needed_write_buf_size)
            c->write_buf_size <<= 1;
        
        char *new_write_buf = malloc(c->write_buf_size);
        memcpy(new_write_buf, c->write_buf + c->write_buf_start, c->write_buf_end - c->write_buf_start);
        memcpy(new_write_buf + c->write_buf_end - c->write_buf_start, buf, count);

        free(c->write_buf);
        c->write_buf = new_write_buf;
        c->write_buf_start = 0;
        c->write_buf_end = needed_write_buf_size;
    } else {
        // we can fit it! (if we try hard enough)
        if (count <= (c->write_buf_size - c->write_buf_end)) {
            // we can fit it easily without moving memory
            memcpy(c->write_buf + c->write_buf_end, buf, count);
        } else {
            // we must move memory
            memmove(c->write_buf, c->write_buf + c->write_buf_start, c->write_buf_end - c->write_buf_start);
            c->write_buf_end -= c->write_buf_start;
            c->write_buf_start = 0;
            memcpy(c->write_buf + c->write_buf_end, buf, count);
            c->write_buf_end += count;
        }
    }

    // flush again
    http_io_client_try_flush(c);
}

static void try_to_remove(struct http_io_client *c, bool force);
void http_client_close(struct http_io_client *c) {
    c->should_be_removed = true;
    try_to_remove(c, false);
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

// force is whether it is already hanged up (so no need to send stuff)
static void try_to_remove(struct http_io_client *c, bool force) {
    int fd = c->fd;

    // remove c only if the write buf is done or if c closed already
    if (force || (c->should_be_removed && c->write_buf_start == c->write_buf_end)) {
        if (c->free_handler != NULL) {
            c->free_handler(c);
            c->free_handler = NULL;
            // LOGGING
            printf("Partially deleted: %d\n", fd);
            // END LOGGING
            // free handler may have written stuff
            if (!force && c->write_buf_start != c->write_buf_end) {
                http_io_client_try_flush(c);
                try_to_remove(c, force);  // try again, hopefully it's done
                return;
            }
        }

        // LOGGING
        printf("Completely deleted: %d\n", fd);
        // END LOGGING
        if (epoll_ctl(http_io_global.epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0) {
            perror("couldn't remove");
            exit(1);
        }

        close(fd);
        free_http_io_client(fd);
    }
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

    // pass 1: mark everything with EPOLLOUT as out_ready
    for (int i = 0; i < nfds; i++) {
        if (!(events[i].events & EPOLLOUT)) continue;

        int fd = events[i].data.fd;
        struct http_io_client *c = http_io_clients[fd];
        if (fd != server_fd && c != NULL && c->__is_an_event_for == NULL) {
            c->out_ready = true;
        }
    }

    for (int i = 0; i < nfds; i++) {
        // LOGGING
        printf("new event!\nfrom %d got %d: epollin(%d) epollout(%d) epollerr(%d)\n", events[i].data.fd, events[i].events, events[i].events & EPOLLIN, events[i].events & EPOLLOUT, events[i].events & EPOLLERR);
        // END LOGGING

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

            if (c->__is_an_event_for != NULL) {
                // is an event for a real client
                c = c->__is_an_event_for;

                c->rd_handler_data.event_fd = peer_fd;
                c->rd_handler_data.events = events[i].events;
                c->rd_handler(c, NULL, 0, c->rd_handler_arg, &c->rd_handler_data);
                c->rd_handler_data.events = 0;
                continue;
            }

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

            try_to_remove(c, events[i].events & EPOLLHUP);
        }
    }
}

void http_io_client_set_read_handler(struct http_io_client *c, http_io_client_read_handler rd_handler, void *arg) {
    c->rd_handler = rd_handler;
    memset(&c->rd_handler_data, 0, sizeof(c->rd_handler_data));
    c->rd_handler_arg = arg;
}

void http_io_client_set_read_handler_immediate(struct http_io_client *c, http_io_client_read_handler rd_handler, void *arg) {
    http_io_client_set_read_handler(c, rd_handler, arg);
    c->rd_handler(c, NULL, 0, arg, &c->rd_handler_data);
}

void http_io_client_set_free_handler(struct http_io_client *c, http_io_client_free_handler free_handler) {
    c->free_handler = free_handler;
}

#endif
