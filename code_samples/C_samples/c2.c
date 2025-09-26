#include <stdlib.h>
int main() {
    int *ptr = malloc(sizeof(int)*5);
    free(ptr);
    *ptr = 10; // use-after-free
    return 0;
}
