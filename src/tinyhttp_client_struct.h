#ifndef _TINYHTTP_CLIENT_STRUCT
#define _TINYHTTP_CLIENT_STRUCT
#include <stddef.h>
struct http_headers;
struct http_io_client;

typedef void (*http_client_free_handler)(struct http_io_client *c);
typedef size_t (*http_io_client_read_handler)(struct http_io_client *c, const char *buf, size_t count, void *arg, void **data);

// Higher level struct for clients
struct http_client_data {
    struct http_headers *headers;
    void *custom_data;

    enum http_request_encoding {
        HTTP_REQUEST_ENCODING_NORMAL,   // have content-length
        HTTP_REQUEST_ENCODING_CHUNKED,  // must be supported for http/1.1
    } request_encoding;

    enum http_response_stage {
        HTTP_RESPONSE_STAGE_STATUS,   // HTTP/1.1 200 OK
        HTTP_RESPONSE_STAGE_HEADERS,  // Content-Type: application/whatever
        HTTP_RESPONSE_STAGE_CONTENT,  // ...
        HTTP_RESPONSE_STAGE_CONTENT_TRANSFER_CHUNKED,  // TODO, for transfer encoding
    } response_stage;

    http_client_free_handler free_handler;  // higher level free handler
    size_t __content_len;  // used by higher level read handler
};
#endif
