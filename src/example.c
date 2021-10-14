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
    struct http_headers *custom_data = c->custom_data;
    if (*datap == 0) {
        printf("HTTP version %s method %s path %s\n", custom_data->http_ver, custom_data->method, custom_data->path);
        printf("Headers are:\n");
        char **headers = custom_data->headers;
        while (*headers != NULL) printf("%s\n", *(headers++));

        struct http_response r = http_response_init(c, "200 OK");
        http_response_set_header(&r, "Content-Type", "text/plain; charset=utf-8");
        http_response_set_content_length(&r, 4);
        http_response_send_content(&r, "1337", 4);
        ++(*datap);
        http_client_close(c);
    }
    return count;
}

static size_t content_req_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    struct http_headers *custom_data = c->custom_data;
    if (*datap == 0) {
        // Read content length
        char *content_length = http_header_by_name(custom_data, "content-length");
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

        printf("HTTP version %s method %s path %s\n", custom_data->http_ver, custom_data->method, custom_data->path);
        printf("Headers are:\n");
        char **headers = custom_data->headers;
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
        struct http_response r = http_response_init(c, "200 OK");
        http_response_set_header(&r, "Content-Type", "text/plain; charset=utf-8");
        http_response_set_content_length(&r, 4);
        http_response_send_content(&r, "1337", 4);
        http_client_close(c);
    }
    return count;
}

static http_io_client_read_handler my_request_router(struct http_headers *data) {
    if (strcmp(data->method, "GET") == 0) {
        return get_req_handler;
    } else {
        return content_req_handler;
    }
}

void logging_free(struct http_io_client *c) {
    printf("Connection closed: %d\n", c->fd);
    header_free_handler(c);
}

static void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    // Read the headers, then call my_request_router to find the right handler
    http_io_client_set_read_handler(c, header_read_handler, my_request_router);
    // If the client disconnects, free the headers
    http_io_client_set_free_handler(c, logging_free);
}

static void err_handler(struct http_io_client *c, int err) {
    char *s;
    if (err == HTTP_EHEADERTOOLARGE) {
        s = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 17\r\n\r\nHeaders Too Large";
    } else {
        s = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\n\r\nServer Error";
    }
    http_client_write(c, s, strlen(s));
}

int main() {
    printf("Hello world!\n");
    return http_serve(8080, new_client_handler, err_handler);
}

#endif
