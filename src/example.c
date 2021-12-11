#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <limits.h>
#include <sys/epoll.h>
#include "tinyhttp.h"

/*
static size_t most_basic_get_req_handler(struct http_io_client *c, const char *buf, size_t count, size_t content_length, struct http_io_client_extra *extra) {
    struct http_headers *headers_struct = c->client_data.headers;

    printf("HTTP version %s method %s path %s\n", headers_struct->http_ver, headers_struct->method, headers_struct->path);
    printf("Headers are:\n");
    char **headers = headers_struct->headers;
    while (*headers != NULL) printf("%s\n", *(headers++));

    http_response_set_status(c, HTTP_200_OK);
    http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
    // http_response_set_content_length(c, 4);
    // if you do not pass a content length it uses transfer-encoding: chunked
    http_response_send_content(c, "1337", 4);
    http_client_close(c);

    return count;
}
*/

void logging_free(struct http_io_client *c, struct http_io_client_extra *extra) {
    printf("Connection closed: %d\n", c->fd);
}


struct serve_files_data {
    int opened_file_fd;
};

void serve_files_free(struct http_io_client *c, struct http_io_client_extra *extra) {
    if (extra->data != NULL) {
        int opened_file_fd = ((struct serve_files_data *)extra->data)->opened_file_fd;
        if (opened_file_fd != -1) close(opened_file_fd);
    }
    free(extra->data);
    logging_free(c, extra);
}

static size_t serve_files(struct http_io_client *c, const char *buf, size_t count, size_t content_length, struct http_io_client_extra *extra) {
    struct serve_files_data *AAAA = extra->data;
    if (AAAA == NULL) {
        // first run
        AAAA = extra->data = calloc(1, sizeof(struct serve_files_data));
        http_client_set_free_handler(c, serve_files_free);

        struct http_headers *headers_struct = c->client_data.headers;

        printf("HTTP version %s method %s path %s\n", headers_struct->http_ver, headers_struct->method, headers_struct->path);
        printf("Headers are:\n");
        char **headers = headers_struct->headers;
        while (*headers != NULL) printf("%s\n", *(headers++));

        char *my_path = malloc(strlen(headers_struct->path) + 2);
        strcpy(my_path, "./");
        strcat(my_path, headers_struct->path + 1);

        printf("Opened path is %s\n", my_path);
        int fd = open(my_path, O_RDONLY);

        free(my_path);

        AAAA->opened_file_fd = fd;
        if (fd == -1) {
            http_client_close_on_error(c, HTTP_EGENERIC);
            return count;
        }

        http_io_add_fd(c, fd);

        printf("Listening to file descriptor %d!\n", fd);

        http_io_submit_read(fd, 1024, 0);

        http_response_set_status(c, HTTP_200_OK);
        http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
    }

    if (extra->event != NULL) {
        struct iocb *iop = extra->event;
        printf("Asynchronously read %zd bytes\n", (ssize_t)extra->res);
        if (extra->res <= 0) {
            // done or error
            http_io_remove_fd(c, AAAA->opened_file_fd);  // optional
            http_client_close(c);
        } else {
            // send and read more
            http_response_send_content(c, (char *)iop->aio_buf, extra->res);
            http_io_submit_read(AAAA->opened_file_fd, 1024, iop->aio_offset + extra->res);
        }
    }

    return count;
}

static size_t content_req_handler(struct http_io_client *c, const char *buf, size_t count, size_t content_length, struct http_io_client_extra *extra) {
    struct http_headers *headers_struct = c->client_data.headers;
    if (extra->data == 0) {
        // Store remaining content_length in extra->data
        extra->data = (void *)content_length;
        printf("Content length is %zu\n", content_length);

        printf("HTTP version %s method %s path %s\n", headers_struct->http_ver, headers_struct->method, headers_struct->path);
        printf("Headers are:\n");
        char **headers = headers_struct->headers;
        while (*headers != NULL) printf("%s\n", *(headers++));
    }
    if (count > 0) {  // print the received bytes
        printf("read %zu bytes: ", count);
        fflush(stdout);
        write(1, buf, count);
        printf("\n");
        if (content_length != SIZE_MAX) extra->data -= count;
    }
    if (extra->data == 0 || (extra->data == ((void *)SIZE_MAX - 1 /* not first run */) && count == 0)) {  // done reading
        http_response_set_status(c, HTTP_200_OK);
        http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
        http_response_set_content_length(c, 4);
        http_response_send_content(c, "1337", 4);
        http_client_close(c);
    }
    if (extra->data == (void *)SIZE_MAX) extra->data = (void *)SIZE_MAX - 1;  /* not first run */
    return count;
}

static http_client_read_handler my_request_router(struct http_headers *headers) {
    if (strcmp(headers->method, "GET") == 0) {
        return serve_files;
    } else {
        return content_req_handler;
    }
}

static void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    http_client_set_router(c, my_request_router);
    // If the client disconnects, log it
    http_client_set_free_handler(c, logging_free);
}

static void err_handler(struct http_io_client *c, int err) {
    if (err == HTTP_EHEADERTOOLARGE) {
        http_response_set_status(c, HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE);
    } else {
        http_response_set_status(c, HTTP_500_INTERNAL_SERVER_ERROR);
    }
    http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
    http_response_set_content_length(c, 12);
    http_response_send_content(c, "Server Error", 12);
}

int main() {
    for (int i = 8080; i < 8100; i++) {
        printf("On port %d\n", i);
        http_serve(i, new_client_handler, err_handler);
    }
    printf("On port %d\n", 8100);
    return http_serve(8100, new_client_handler, err_handler);
}

#endif
