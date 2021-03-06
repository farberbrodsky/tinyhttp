#ifndef _TINYHTTP_CLIENT_STRUCT
#define _TINYHTTP_CLIENT_STRUCT
#include <stddef.h>
#include <stdint.h>
#include <linux/aio_abi.h>
struct http_headers;
struct http_io_client;

struct http_io_client_extra {
    void *data;
    struct iocb *event;  // relevant iocb that has returned or NULL
    __s64 res;           // result code for this event
    __s64 res2;	         // secondary result
};

typedef void (*http_client_free_handler)(struct http_io_client *c, struct http_io_client_extra *extra);

// Higher level struct for clients
struct http_client_data {
    struct http_headers *headers;

    enum http_request_encoding {
        HTTP_REQUEST_ENCODING_NORMAL,   // have content-length
        HTTP_REQUEST_ENCODING_CHUNKED,  // must be supported for http/1.1
    } request_encoding;
    void *http_request_internal;

    enum http_response_stage {
        HTTP_RESPONSE_STAGE_STATUS,   // HTTP/1.1 200 OK
        HTTP_RESPONSE_STAGE_HEADERS,  // Content-Type: application/whatever
        HTTP_RESPONSE_STAGE_CONTENT,  // ...
        HTTP_RESPONSE_STAGE_CONTENT_TRANSFER_CHUNKED,  // for transfer encoding
    } response_stage;

    http_client_free_handler free_handler;  // higher level free handler
    size_t __content_len;  // used by higher level read handler
};
#endif
