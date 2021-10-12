#ifndef _TINYHTTP_H
#define _TINYHTTP_H
#define MAX_HEADER_SIZE 8192
#include "tinyhttp_io.h"

// TODO free client_data at some point

struct http_headers {
    char header[MAX_HEADER_SIZE + 1];  // like the original header but many characters are replaced with null
    char *method;
    char *path;
    char *http_ver;
    char **headers;  // like envp, a list of char *s of different headers, null terminated
};

#define HTTP_EGENERIC 0
#define HTTP_EHEADERTOOLARGE 3
typedef http_io_client_read_handler (*http_request_router)(struct http_headers *data);

size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap);
void header_free_handler(struct http_io_client *c);

#endif
