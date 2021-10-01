#include "stdio.h"
#include "tinyhttp.h"

size_t client_read_handler(struct http_io_client *c, const char *buf, size_t count, void **data) {
    printf("Read from %d: ", c->fd);
    for (size_t i = 0; i < count; i++) {
        putc(((char *)buf)[i], stdout);
    }
    return count;  // used up everything
}

void new_client_handler(struct http_io_client *c) {
    printf("Connection!!! %d\n", c->fd);
    http_io_client_set_read_handler(c, client_read_handler);
}

int main() {
    printf("Hello world!\n");
    printf("%d\n", http_serve(8080, new_client_handler));
}
