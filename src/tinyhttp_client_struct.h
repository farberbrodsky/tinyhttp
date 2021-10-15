#ifndef _TINYHTTP_CLIENT_STRUCT
#define _TINYHTTP_CLIENT_STRUCt
struct http_headers;

// Higher level struct for clients
struct http_client_data {
    struct http_headers *headers;
    void *custom_data;
};
#endif
