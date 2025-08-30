#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function prototypes
void print_sum(int value);
static void static_function(void);

// Simple hello world with some complexity for analysis
int main(int argc, char *argv[]) {
    printf("Hello, World from C!\n");

    // Some basic operations to create interesting disassembly
    int sum = 0;
    for (int i = 0; i < argc; i++) {
        sum += strlen(argv[i]);
    }

    // Function call
    print_sum(sum);

    // Call static function
    static_function();

    return EXIT_SUCCESS;
}

void print_sum(int value) {
    printf("Total argument length: %d\n", value);
}

// Global variable
int global_counter = 42;

// Static function
static void static_function(void) {
    static int static_var = 0;
    static_var++;
    printf("Static function called %d times\n", static_var);
}
