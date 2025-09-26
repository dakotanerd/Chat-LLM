#include <stdio.h>
int main() {
    char buf[20];
    printf(buf); // format string attack possible
    return 0;
}
