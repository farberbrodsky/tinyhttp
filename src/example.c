#include "stdio.h"
#include "tinyhttp.h"

int main() {
    printf("Hello world!\n");
    printf("%d\n", http_serve(8080));
}
