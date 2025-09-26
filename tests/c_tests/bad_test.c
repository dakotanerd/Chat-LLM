#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USERS 10

typedef struct {
    int id;
    char username[50];
    int age;
} User;

void print_user(User *u) {
    printf("User ID: %d\n", u->id);
    printf("Username: %s\n", u->username);
    printf("Age: %d\n", u->age);
}

int main() {
    User users[MAX_USERS];
    int count = 0;
    char input[256];

    // Vulnerability 1: Buffer overflow with gets()
    printf("Enter your name: ");
    gets(input);  // unsafe

    strncpy(users[0].username, input, sizeof(users[0].username)); // okay but overflow already possible
    users[0].id = 1;
    users[0].age = 20;

    // Vulnerability 2: Command execution
    char cmd[100];
    sprintf(cmd, "echo Hello %s", users[0].username); // vulnerable to injection
    system(cmd);  // unsafe

    print_user(&users[0]);

    return 0;
}
