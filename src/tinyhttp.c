#include <stdio.h>
#include <ctype.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include "stdint.h"
#include "tinyhttp.h"

static void http_free_handler(struct http_io_client *c);
size_t header_read_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, struct http_io_client_extra *extra) {
    uint32_t end_of_headers = be32toh(0x0d0a0d0a);
    uint32_t http = be32toh(0x48545450);
    uint16_t newline = be16toh(0x0d0a);

    struct http_headers *headers_struct = c->client_data.headers;

    if (headers_struct == NULL) {
        headers_struct = malloc(sizeof(struct http_headers));
        headers_struct->path = NULL;
        headers_struct->method = NULL;
        headers_struct->headers = NULL;
        c->client_data.headers = headers_struct;
        headers_struct->header[0] = '\0';

        http_io_client_set_free_handler(c, http_free_handler);
    }

    unsigned int *h_len = (unsigned int *)(&extra->data);  // store length directly in datap
    char *header = headers_struct->header;

    size_t final_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (*h_len == MAX_HEADER_SIZE) break;  // TODO should close client, this will probably cause bugs
        ++final_count;
        header[(*h_len)++] = buf[i];

        if (*h_len >= 4 && *(uint32_t *)(&header[*h_len - 4]) == end_of_headers) {
            // parse headers, search for first newline
            // first line is method, path, version
            char *h_ptr = header;
            char *h_end = header + *h_len - 2;
            char **headers = calloc(1, sizeof(char *));

            // check http version
            while (h_ptr != h_end && *((uint32_t *)h_ptr) != http) ++h_ptr;
            headers_struct->http_ver = h_ptr;
            while (h_ptr != h_end && *((uint16_t *)h_ptr) != newline) ++h_ptr;
            *h_ptr = '\0';
            if (strcmp(headers_struct->http_ver, "HTTP/1.1") != 0) {
                http_client_close_on_error(c, HTTP_EGENERIC);  // not http/1.1, this is bad
                break;
            }

            // look for method and path
            h_ptr = header;
            headers_struct->method = h_ptr;
            while (h_ptr != headers_struct->http_ver && *h_ptr != ' ') ++h_ptr;
            *h_ptr = '\0';
            headers_struct->path = ++h_ptr;
            while (h_ptr != headers_struct->http_ver && *h_ptr != ' ') ++h_ptr;
            *h_ptr = '\0';

            // rest of the headers...
            for (int i = 0; i < 10; i++) {
                while (h_ptr != h_end && *h_ptr != '\r') ++h_ptr;
                *h_ptr = '\0';
                h_ptr += 2;  // \r\n
                if (h_ptr >= h_end) {
                    h_ptr = h_end;
                    break;
                }
                headers = realloc(headers, (i + 2) * sizeof(char *));
                headers[i] = h_ptr;
                headers[i + 1] = NULL;
            }

            headers_struct->headers = headers;
            http_client_read_handler rd_handler = ((http_request_router)(arg))(headers_struct);
            if (rd_handler == NULL) {
                // client close
                http_client_close_on_error(c, HTTP_EGENERIC);
                break;
            }
            http_client_set_read_handler(c, rd_handler);
            break;
        }
    }
    return final_count;
}

// Frees headers from c->client_data and finishes some encodings
static void http_free_handler(struct http_io_client *c) {
    if (c->client_data.free_handler != NULL) c->client_data.free_handler(c, &c->rd_handler_data);

    struct http_headers *headers_struct = c->client_data.headers;
    if (headers_struct == NULL) return;
    free(headers_struct->headers);
    free(headers_struct);

    if (c->client_data.http_request_internal != NULL) free(c->client_data.http_request_internal);

    if (c->client_data.response_stage == HTTP_RESPONSE_STAGE_CONTENT_TRANSFER_CHUNKED) {
        http_io_client_write(c, "0\r\n\r\n", 5);
    } else if (c->client_data.response_stage == HTTP_RESPONSE_STAGE_HEADERS) {
        http_io_client_write(c, "\r\n", 2);
    }
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


static const char http_1_1_[] = {'H', 'T', 'T', 'P', '/', '1', '.', '1', ' '};

void http_response_set_status(struct http_io_client *c, char *status) {
    size_t status_len = strlen(status);
    size_t full_status_line_len = sizeof(http_1_1_) + status_len + 2;  // 2 is for \r\n
    char *full_status_line = alloca(full_status_line_len);
    memcpy(full_status_line, http_1_1_, sizeof(http_1_1_));
    memcpy(full_status_line + sizeof(http_1_1_), status, status_len);
    full_status_line[full_status_line_len - 2] = '\r';
    full_status_line[full_status_line_len - 1] = '\n';
    http_io_client_write(c, full_status_line, full_status_line_len);
    c->client_data.response_stage = HTTP_RESPONSE_STAGE_HEADERS;
}

void http_response_set_header(struct http_io_client *c, char *key, char *val) {
    if (c->client_data.response_stage != HTTP_RESPONSE_STAGE_HEADERS) {
        fputs("http_response_set_header: wrong stage!\n", stderr);
    }

    size_t key_len = strlen(key);
    size_t val_len = strlen(val);
    size_t header_len = key_len + val_len + 3;  // 3 is for : and \r\n
    char *header = malloc(header_len);

    memcpy(header, key, key_len);
    header[key_len] = ':';
    memcpy(header + key_len + 1, val, val_len);
    header[header_len - 2] = '\r';
    header[header_len - 1] = '\n';
    http_io_client_write(c, header, header_len);
    free(header);
}

void http_response_set_content_length(struct http_io_client *c, size_t content_length) {
    if (c->client_data.response_stage != HTTP_RESPONSE_STAGE_HEADERS) {
        fputs("http_response_set_content_length: wrong stage!\n", stderr);
        return;
    }

    char content_length_str[32];
    snprintf(content_length_str, sizeof(content_length_str), "%zu\r\n", content_length);
    http_response_set_header(c, "Content-Length", content_length_str);

    c->client_data.response_stage = HTTP_RESPONSE_STAGE_CONTENT;
}

void http_response_send_content(struct http_io_client *c, char *buf, size_t count) {
    if (c->client_data.response_stage != HTTP_RESPONSE_STAGE_CONTENT
     && c->client_data.response_stage != HTTP_RESPONSE_STAGE_CONTENT_TRANSFER_CHUNKED) {
        if (c->client_data.response_stage == HTTP_RESPONSE_STAGE_HEADERS) {
            // go to transfer chunked
            http_response_set_header(c, "Transfer-Encoding", "chunked\r\n");
            c->client_data.response_stage = HTTP_RESPONSE_STAGE_CONTENT_TRANSFER_CHUNKED;
        } else {
            fputs("http_response_send_content: wrong stage!\n", stderr);
            return;
        }
    }
    if (c->client_data.response_stage == HTTP_RESPONSE_STAGE_CONTENT_TRANSFER_CHUNKED) {
        char count_str[32];
        int count_str_len = snprintf(count_str, sizeof(count_str), "%zX\r\n", count);
        http_io_client_write(c, count_str, count_str_len);
        http_io_client_write(c, buf, count);
        http_io_client_write(c, "\r\n", 2);
    } else {
        http_io_client_write(c, buf, count);
    }
}

struct http_request_internal {
    size_t chunk_size;
    int chunk_line_buf_len;
    char chunk_line_buf[32];
};

static size_t http_content_rd_handler(struct http_io_client *c, const char *buf, size_t count, void *arg, struct http_io_client_extra *extra) {
    if (c->client_data.request_encoding == HTTP_REQUEST_ENCODING_CHUNKED) {
        struct http_request_internal *i = c->client_data.http_request_internal;
        if (i->chunk_size != 0) {
            if (count > i->chunk_size)
                count = i->chunk_size;
            size_t result = ((http_client_read_handler)arg)(c, buf, count, c->client_data.__content_len, extra);

            if (i->chunk_size == SIZE_MAX) // first run
                i->chunk_size = 0;
            else
                i->chunk_size -= result;
            return result;
        } else {
            size_t result = 0;
            // read the next line for chunk size
            while (result < count && (
                (i->chunk_line_buf_len < 3) ||
                (i->chunk_line_buf[i->chunk_line_buf_len - 2] != '\r' || i->chunk_line_buf[i->chunk_line_buf_len - 1] != '\n'))) {
                i->chunk_line_buf[i->chunk_line_buf_len++] = *(buf++);
                result++;

                if (i->chunk_line_buf_len >= 31) {
                    http_client_close_on_error(c, HTTP_EGENERIC);
                    return count;
                }
            }
            if (i->chunk_line_buf[i->chunk_line_buf_len - 2] == '\r' && i->chunk_line_buf[i->chunk_line_buf_len - 1] == '\n') {
                // we got a chunk line! that has the chunk size
                i->chunk_line_buf[i->chunk_line_buf_len] = '\0';
                if (i->chunk_line_buf[0] == '\r')
                    sscanf(i->chunk_line_buf + 2, "%zX", &i->chunk_size);
                else
                    sscanf(i->chunk_line_buf, "%zX", &i->chunk_size);
                i->chunk_line_buf_len = 0;
                if (i->chunk_size == 0) {
                    // the last chunk
                    return ((http_client_read_handler)arg)(c, NULL, 0, c->client_data.__content_len, extra);
                }
            }
            return result;
        }
    } else {
        return ((http_client_read_handler)arg)(c, buf, count, c->client_data.__content_len, extra);
    }
}

void http_client_set_read_handler(struct http_io_client *c, http_client_read_handler rd_handler) {
    char *transfer_encoding = http_header_by_name(c->client_data.headers, "transfer-encoding");
    size_t content_length = 0;
    // TODO: do an error if the transfer encoding isn't chunked
    if (transfer_encoding != NULL && !strcmp(transfer_encoding, "chunked")) {
        c->client_data.request_encoding = HTTP_REQUEST_ENCODING_CHUNKED;
        content_length = SIZE_MAX;
        struct http_request_internal *i = calloc(1, sizeof(struct http_request_internal));
        i->chunk_size = SIZE_MAX;  // on first run, it is SIZE_MAX
        c->client_data.http_request_internal = i;
    } else {
        c->client_data.request_encoding = HTTP_REQUEST_ENCODING_NORMAL;
        char *content_length_s = http_header_by_name(c->client_data.headers, "content-length");
        if (content_length_s != NULL) {
            content_length = strtoll(content_length_s, NULL, 10);
        }
    }
    c->client_data.__content_len = content_length;
    http_io_client_set_read_handler_immediate(c, http_content_rd_handler, rd_handler);
}

void http_client_set_free_handler(struct http_io_client *c, http_client_free_handler free_handler) {
    c->client_data.free_handler = free_handler;
}

void http_client_set_router(struct http_io_client *c, http_request_router router) {
    http_io_client_set_read_handler(c, header_read_handler, router);
}
