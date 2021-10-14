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

// REQUEST PARSING

// Reads headers, then calls the http_request_router in arg.
// After that it sets the read handler to the result of the router, with the argument being the headers.
// The headers are also stored in c->custom_data.
size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap);
// Frees headers from c->custom_data
void header_free_handler(struct http_io_client *c);
// Returns the value of a header, or NULL if it does not exist
// name must be lowercase
char *http_header_by_name(struct http_headers *h, char *name);

// RESPONSE CONSTRUCTION
struct http_response {
    struct http_io_client *client;

    enum http_response_stage {
        HTTP_RESPONSE_STAGE_HEADERS,  // Content-Type: application/whatever
        HTTP_RESPONSE_STAGE_CONTENT,  // ...
        HTTP_RESPONSE_STAGE_CONTENT_TRANSFER,  // TODO, for transfer encoding
    } stage;
};
// e.g. c, "200 OK"
struct http_response http_response_init(struct http_io_client *client, char *status);
// e.g. "Content-Type", "application/whatever"
void http_response_set_header(struct http_response *r, char *key, char *value);
// TODO: support transfer encoding if you don't know in advance how large the output will be
void http_response_set_content_length(struct http_response *r, size_t content_length);
// You can send your content in parts
void http_response_send_content(struct http_response *r, char *buf, size_t count);

#endif
