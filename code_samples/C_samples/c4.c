#include <stdio.h>
int main() {
    char buf[20];
    gets(buf); // unsafe, can overflow
    printf("Hello %s\n", buf);
    return 0;
}
