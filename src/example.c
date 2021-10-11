#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include "tinyhttp_io.h"

#define MAX_HEADER_SIZE 8192

struct client_data {
    char header[MAX_HEADER_SIZE + 1];  // like the original header but many characters are replaced with null
    char *method;
    char *path;
    char *http_ver;
    char **headers;  // like envp, a list of char *s of different headers, null terminated
};

// TODO free client_data at some point

static size_t normal_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    struct client_data *custom_data = c->custom_data;
    if (*datap == 0) {
        char *s = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\n1337";

        char **headers = custom_data->headers;
        while (*headers != NULL) printf("%s\n", *(headers++));
        http_client_write(c, s, strlen(s));
        ++(*datap);
    }
    return count;
}

static http_io_client_read_handler my_request_router(struct client_data *data) {
    return normal_read_handler;
}

typedef http_io_client_read_handler (*http_request_router)(struct client_data *data);
static size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    uint32_t end_of_headers = be32toh(0x0d0a0d0a);
    uint32_t http = be32toh(0x48545450);
    uint16_t newline = be16toh(0x0d0a);

    struct client_data *custom_data = c->custom_data;
    char *header = custom_data->header;
    unsigned int h_len = (uintptr_t)*datap;  // store length directly in datap

    size_t final_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (h_len == MAX_HEADER_SIZE) break;  // TODO should close client, this will probably cause bugs
        ++final_count;
        header[h_len++] = buf[i];

        if (h_len >= 4 && *(uint32_t *)(&header[h_len - 4]) == end_of_headers) {
            // parse headers, search for first newline
            // first line is method, path, version
            char *h_ptr = header;
            char *h_end = header + h_len - 2;
            char **headers = calloc(1, sizeof(char *));

            // check http version
            while (h_ptr != h_end && *((uint32_t *)h_ptr) != http) ++h_ptr;
            custom_data->http_ver = h_ptr;
            while (h_ptr != h_end && *((uint16_t *)h_ptr) != newline) ++h_ptr;
            *h_ptr = '\0';
            if (strcmp(custom_data->http_ver, "HTTP/1.1") != 0) {
                printf("Not http/1.1... should probably do a bad response\n");
            }

            // look for method and path
            h_ptr = header;
            custom_data->method = h_ptr;
            while (h_ptr != custom_data->http_ver && *h_ptr != ' ') ++h_ptr;
            *h_ptr = '\0';
            custom_data->path = ++h_ptr;
            while (h_ptr != custom_data->http_ver && *h_ptr != ' ') ++h_ptr;
            *h_ptr = '\0';
            printf("HTTP version %s method %s path %s\n", custom_data->http_ver, custom_data->method, custom_data->path);

            // rest of the headers...
            for (int i = 0; i < 10; i++) {
                while (h_ptr != h_end && *h_ptr != '\n') ++h_ptr;
                *(h_ptr++) = '\0';
                if (h_ptr >= h_end) {
                    h_ptr = h_end;
                    break;
                }
                headers = realloc(headers, (i + 2) * sizeof(char *));
                headers[i] = h_ptr;
                headers[i + 1] = NULL;
            }

            custom_data->headers = headers;
            http_io_client_read_handler rd_handler = ((http_request_router)(arg))(custom_data);
            http_io_client_set_read_handler(c, rd_handler, NULL);
            rd_handler(c, buf, 0, NULL, datap);
            break;
        }
    }
    return final_count;
}

static void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    struct client_data *client_data = malloc(sizeof(struct client_data));
    client_data->path = NULL;
    client_data->method = NULL;
    client_data->headers = NULL;
    c->custom_data = client_data;
    ((struct client_data *)c->custom_data)->header[0] = '\0';
    http_io_client_set_read_handler(c, header_read_handler, my_request_router);
}

int main() {
    printf("Hello world!\n");
    fprintf(stderr, "%d\n", http_serve(8080, new_client_handler));
}
