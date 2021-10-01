#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include "tinyhttp.h"

#define MAX_HEADER_SIZE 8192

size_t normal_read_handler(struct http_io_client *c, const char *buf, size_t count, void **datap) {
    if (*datap == 0) {
        char *s = "HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\n1337";
        http_client_write(c, s, strlen(s));
        ++(*datap);
    }
    printf("Got from %d: ", c->fd);
    for (size_t i = 0; i < count; i++) {
        putc(buf[i], stdout);
    }
    printf("\n");
    return count;
}

size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void **datap) {
    uint32_t end_of_headers = be32toh(0x0d0a0d0a);
    struct http_header {
        char header[MAX_HEADER_SIZE];  // like the original header but many characters are replaced with null
        int len;
    };

    if (*datap == NULL) {
        *datap = malloc(sizeof(struct http_header));
        ((struct http_header *)(*datap))->len = 0;
    }
    struct http_header *data = *datap;

    size_t final_count = count;
    for (size_t i = 0; i < count; i++) {
        if (data->len == MAX_HEADER_SIZE) break;  // TODO should close client, this will probably cause bugs
        --final_count;
        data->header[data->len++] = buf[i];
        if (data->len >= 4 && *(uint32_t *)(&data->header[data->len - 4]) == end_of_headers) {
            printf("End of headers!\n");
            free(data);
            http_io_client_set_read_handler(c, normal_read_handler);
            break;
        }
    }
    return final_count;
}

void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    http_io_client_set_read_handler(c, header_read_handler);
}

int main() {
    printf("Hello world!\n");
    printf("%d\n", http_serve(8080, new_client_handler));
}
