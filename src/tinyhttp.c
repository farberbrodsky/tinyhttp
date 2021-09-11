#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "tinyhttp.h"
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define BACKLOG 32
#define MAX_EPOLL_EVENTS 8
#define READ_BUF_SIZE 2048


static struct http_io_data_struct {
    int epoll_fd;
    int server_fd;
} http_io_data;


static void http_io_respond();
int http_serve(int port_num) {
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
        return -3;
    }
    freeaddrinfo(addrinfo_result);

    if (listen(server_fd, BACKLOG) != 0) {
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

    http_io_data.epoll_fd = epoll_fd;
    http_io_data.server_fd = server_fd;
    while (true) http_io_respond();

    fprintf(stderr, "Something failed!\n");
    return 0;
}

static void http_io_respond() {
    int epoll_fd = http_io_data.epoll_fd;
    int server_fd = http_io_data.server_fd;

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
            int peer_fd = accept4(server_fd, (struct sockaddr *)&peer_address, &peer_address_len, SOCK_NONBLOCK);
            if (peer_fd == -1) continue;

            ev.events = EPOLLIN | EPOLLET;
            ev.data.fd = peer_fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, peer_fd, &ev) != 0) {
                perror("couldn't add to epoll");
                close(server_fd);
                close(epoll_fd);
                close(peer_fd);
                exit(1);
            }
            printf("Connection: %d\n", peer_fd);
            write(peer_fd, "welcome!\n", 9);
        } else {
            int peer_fd = events[i].data.fd;
            char buf[READ_BUF_SIZE];
            ssize_t read_count = read(peer_fd, buf, READ_BUF_SIZE);
            if (read_count == 0 || (read_count == -1 && errno != EAGAIN)) {
                // socket closed
                printf("Closed: %d\n", peer_fd);
                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, peer_fd, NULL) != 0) {
                    perror("couldn't remove");
                    exit(1);
                }
                close(peer_fd);
            }
            else {
                printf("Read %d bytes from %d\n", (int)read_count, peer_fd);
                write(peer_fd, buf, read_count);
            }
        }
    }
}

#endif
