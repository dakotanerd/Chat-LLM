#include <stdio.h>
#include <string.h>
int main() {
    char buf[10];
    strcpy(buf, "This string is too long!"); // buffer overflow
    printf("%s\n", buf);
    return 0;
}
