#include <stdio.h>
#include <ctype.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include "stdint.h"
#include "tinyhttp.h"

size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, void **datap) {
    uint32_t end_of_headers = be32toh(0x0d0a0d0a);
    uint32_t http = be32toh(0x48545450);
    uint16_t newline = be16toh(0x0d0a);

    struct http_headers *custom_data = c->custom_data;

    if (custom_data == NULL) {
        custom_data = malloc(sizeof(struct http_headers));
        custom_data->path = NULL;
        custom_data->method = NULL;
        custom_data->headers = NULL;
        c->custom_data = custom_data;
        custom_data->header[0] = '\0';
    }

    unsigned int h_len = (uintptr_t)*datap;  // store length directly in datap
    char *header = custom_data->header;

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
                http_client_close_on_error(c, HTTP_EGENERIC);  // not http/1.1, this is bad
                break;
            }

            // look for method and path
            h_ptr = header;
            custom_data->method = h_ptr;
            while (h_ptr != custom_data->http_ver && *h_ptr != ' ') ++h_ptr;
            *h_ptr = '\0';
            custom_data->path = ++h_ptr;
            while (h_ptr != custom_data->http_ver && *h_ptr != ' ') ++h_ptr;
            *h_ptr = '\0';

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
            if (rd_handler == NULL) {
                // client close
                http_client_close_on_error(c, HTTP_EGENERIC);
                break;
            }
            http_io_client_set_read_handler(c, rd_handler, NULL);
            rd_handler(c, buf, 0, NULL, datap);
            break;
        }
    }
    return final_count;
}

void header_free_handler(struct http_io_client *c) {
    struct http_headers *custom_data = c->custom_data;
    if (custom_data == NULL) return;
    free(custom_data->headers);
    free(custom_data);
}

char *http_header_by_name(struct http_headers *h, char *name) {
    char **headers_p = h->headers;
    char *header;
    while ((header = *(headers_p++)) != NULL) {
        char *name_p = name;
        // Compare the header and name, until one of them terminates
        while (*header != '\0' && *header != ':' && *name_p != '\0' && tolower(*(header++)) == *(name_p++));
        // Check that both have terminated correctly
        if (*header == ':' && *name_p == '\0') {
            // Skip the colon, and if there is a space before the header value, go to the next character
            if (*(++header) == ' ') ++header;
            return header;
        }
    }
    return NULL;
}
