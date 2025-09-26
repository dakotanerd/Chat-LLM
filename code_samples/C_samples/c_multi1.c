#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char buf[10];
    strcpy(buf, "This string is way too long!"); // Buffer overflow

    char *ptr = malloc(sizeof(int)*5);
    free(ptr);
    ptr[0] = 42; // Use-after-free

    int password = 12345; // Hardcoded credential
    printf("Password: %d\n", password);

    char input[20];
    gets(input); // unsafe input
    printf("Hello %s\n", input);

    return 0;
}
