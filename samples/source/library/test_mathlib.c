// test_mathlib.c - Test program for mathlib shared library
#include <stdio.h>
#include <stdlib.h>
#include "mathlib.h"

// Callback function for testing
int square_callback(int x) {
    return x * x;
}

int main(int argc, char* argv[]) {
    printf("Testing mathlib version %s\n", mathlib_version());
    printf("Version: %d.%d\n", mathlib_version_major(), mathlib_version_minor());
    
    // Test basic operations
    printf("\nBasic Operations:\n");
    printf("10 + 5 = %d\n", mathlib_add(10, 5));
    printf("10 - 5 = %d\n", mathlib_subtract(10, 5));
    printf("10 * 5 = %d\n", mathlib_multiply(10, 5));
    printf("10 / 5 = %.2f\n", mathlib_divide(10.0, 5.0));
    
    // Test advanced operations
    printf("\nAdvanced Operations:\n");
    printf("Factorial(5) = %lld\n", mathlib_factorial(5));
    printf("Fibonacci(10) = %d\n", mathlib_fibonacci(10));
    printf("GCD(48, 18) = %d\n", mathlib_gcd(48, 18));
    printf("Is 17 prime? %s\n", mathlib_is_prime(17) ? "Yes" : "No");
    printf("Is 18 prime? %s\n", mathlib_is_prime(18) ? "Yes" : "No");
    
    // Test array operations
    int test_array[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int array_size = sizeof(test_array) / sizeof(test_array[0]);
    
    printf("\nArray Operations on [1..10]:\n");
    printf("Sum = %d\n", mathlib_array_sum(test_array, array_size));
    printf("Average = %.2f\n", mathlib_array_average(test_array, array_size));
    printf("Max = %d\n", mathlib_array_max(test_array, array_size));
    printf("Min = %d\n", mathlib_array_min(test_array, array_size));
    
    // Test callback
    printf("\nCallback Test:\n");
    printf("Square of 7 = %d\n", mathlib_apply_operation(7, square_callback));
    
    // Test random number generation
    printf("\nRandom Number Generation:\n");
    mathlib_set_global_seed(42);
    printf("Seed set to: %u\n", mathlib_get_global_seed());
    printf("Random numbers: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", mathlib_random() % 100);
    }
    printf("\n");
    
    // Test point distance
    MathPoint p1 = {0.0, 0.0};
    MathPoint p2 = {3.0, 4.0};
    printf("\nDistance between (0,0) and (3,4) = %.2f\n", 
           mathlib_point_distance(&p1, &p2));
    
    return 0;
}