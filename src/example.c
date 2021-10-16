#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <limits.h>
#include "tinyhttp.h"

static size_t get_req_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    struct http_headers *headers_struct = c->client_data.headers;

    printf("HTTP version %s method %s path %s\n", headers_struct->http_ver, headers_struct->method, headers_struct->path);
    printf("Headers are:\n");
    char **headers = headers_struct->headers;
    while (*headers != NULL) printf("%s\n", *(headers++));

    http_response_set_status(c, "200 OK");
    http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
    http_response_set_content_length(c, 4);
    http_response_send_content(c, "1337", 4);
    http_client_close(c);

    return count;
}

static size_t content_req_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    struct http_headers *headers_struct = c->client_data.headers;
    if (*datap == 0) {
        // Read content length
        char *content_length = http_header_by_name(headers_struct, "content-length");
        if (content_length == NULL) {
            http_client_close_on_error(c, HTTP_EGENERIC);
            return count;
        }
        long long content_length_val = strtoll(content_length, NULL, 10);
        if (content_length_val == LLONG_MIN || content_length_val == LLONG_MAX) {
            http_client_close_on_error(c, HTTP_EGENERIC);
            return count;
        }
        *datap = (void *)content_length_val + 1;  // how many bytes we need, plus 1

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
        *datap -= count;
    }
    if (*datap == (void *)1) {  // done reading
        http_response_set_status(c, "200 OK");
        http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
        http_response_set_content_length(c, 4);
        http_response_send_content(c, "1337", 4);
        http_client_close(c);
    }
    return count;
}

static http_io_client_read_handler my_request_router(struct http_headers *headers) {
    if (strcmp(headers->method, "GET") == 0) {
        return get_req_handler;
    } else {
        return content_req_handler;
    }
}

void logging_free(struct http_io_client *c) {
    printf("Connection closed: %d\n", c->fd);
}

static void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    http_client_set_router(c, my_request_router);
    // If the client disconnects, log it
    http_client_set_free_handler(c, logging_free);
}

static void err_handler(struct http_io_client *c, int err) {
    if (err == HTTP_EHEADERTOOLARGE) {
        http_response_set_status(c, "431 Request Header Fields Too Large");
    } else {
        http_response_set_status(c, "500 Internal Server Error");
    }
    http_response_set_header(c, "Content-Type", "text/plain; charset=utf-8");
    http_response_set_content_length(c, 12);
    http_response_send_content(c, "Server Error", 12);
}

int main() {
    printf("Hello world!\n");
    return http_serve(8080, new_client_handler, err_handler);
}

#endif
