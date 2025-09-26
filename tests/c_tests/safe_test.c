#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USERS 100

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

int add_user(User users[], int *count, int id, const char *username, int age) {
    if (*count >= MAX_USERS) return -1;
    users[*count].id = id;
    strncpy(users[*count].username, username, sizeof(users[*count].username) - 1);
    users[*count].username[sizeof(users[*count].username) - 1] = '\0';
    users[*count].age = age;
    (*count)++;
    return 0;
}

int main() {
    User users[MAX_USERS];
    int count = 0;

    add_user(users, &count, 1, "Alice", 25);
    add_user(users, &count, 2, "Bob", 30);
    add_user(users, &count, 3, "Charlie", 22);

    for (int i = 0; i < count; i++) {
        print_user(&users[i]);
    }

    // Sorting users by age
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (users[i].age > users[j].age) {
                User temp = users[i];
                users[i] = users[j];
                users[j] = temp;
            }
        }
    }

    printf("\nUsers sorted by age:\n");
    for (int i = 0; i < count; i++) {
        print_user(&users[i]);
    }

    return 0;
}
