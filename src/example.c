#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include "tinyhttp.h"

static size_t normal_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    struct http_headers *custom_data = c->custom_data;
    if (*datap == 0) {
        char *s = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\n1337";

        char **headers = custom_data->headers;
        while (*headers != NULL) printf("%s\n", *(headers++));
        http_client_write(c, s, strlen(s));
        ++(*datap);
    }
    return count;
}

static http_io_client_read_handler my_request_router(struct http_headers *data) {
    return normal_read_handler;
}

static void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    http_io_client_set_read_handler(c, header_read_handler, my_request_router);
}

int main() {
    printf("Hello world!\n");
    return http_serve(8080, new_client_handler);
}
