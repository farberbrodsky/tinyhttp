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
// The headers are also stored in c->client_data.
size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap);
// Returns the value of a header, or NULL if it does not exist
// name must be lowercase
char *http_header_by_name(struct http_headers *h, char *name);

// RESPONSE CONSTRUCTION
// e.g. c, "200 OK"
#define HTTP_200_OK "200 OK"
#define HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE "431 Request Header Fields Too Large"
#define HTTP_500_INTERNAL_SERVER_ERROR "500 Internal Server Error"
void http_response_set_status(struct http_io_client *c, char *status);
// e.g. "Content-Type", "application/whatever"
void http_response_set_header(struct http_io_client *c, char *key, char *value);
// TODO: support transfer encoding if you don't know in advance how large the output will be
void http_response_set_content_length(struct http_io_client *c, size_t content_length);
// You can send your content in parts
void http_response_send_content(struct http_io_client *c, char *buf, size_t count);

// Sets your free handler, plus the header free handler
void http_client_set_free_handler(struct http_io_client *c, http_client_free_handler free_handler);
// Equivalent to http_io_client_set_read_handler(c, header_read_handler, router)
void http_client_set_router(struct http_io_client *c, http_request_router router);

#endif
