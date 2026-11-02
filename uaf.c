#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct User {
    char username[16];
    int is_admin;
};

int main() {
    // 1. Allocate memory for a user
    struct User *user = malloc(sizeof(struct User));
    strcpy(user->username, "guest");
    user->is_admin = 0;

    printf("Before free: user at %p, username: %s, is_admin: %d\n",
           (void*)user, user->username, user->is_admin);

    // 2. Free the memory
    free(user);

    // 3. UAF: Access the freed memory
    // The pointer 'user' is now dangling.
    printf("After free: user at %p, username: %s, is_admin: %d\n",
           (void*)user, user->username, user->is_admin);

    return 0;
}
