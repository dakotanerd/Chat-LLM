#include <stdio.h>
#include <string.h>

int sum(int a, int b) {
    return a + b;
}

int main() {
    int total = sum(5, 10);
    printf("Total: %d\n", total);
    return 0;
}
