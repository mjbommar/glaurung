// mathlib.c - Implementation of sample shared library
#include "mathlib.h"
#include <math.h>
#include <stdlib.h>
#include <limits.h>

// Define export macro for Windows
#ifdef _WIN32
    #define MATHLIB_EXPORTS
#endif

// Version constants
#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_STRING "1.0.0"

// Global state (for testing data sections)
static unsigned int g_random_seed = 12345;
static int g_call_count = 0;

// Constructor/Destructor attributes for ELF
#ifdef __GNUC__
    __attribute__((constructor))
    static void mathlib_init(void) {
        g_random_seed = 12345;
        g_call_count = 0;
    }
    
    __attribute__((destructor))
    static void mathlib_cleanup(void) {
        // Cleanup code if needed
    }
#endif

// DLL entry point for Windows
#ifdef _WIN32
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            g_random_seed = 12345;
            g_call_count = 0;
            break;
        case DLL_PROCESS_DETACH:
            // Cleanup
            break;
    }
    return TRUE;
}
#endif

// Version functions
MATHLIB_API const char* mathlib_version(void) {
    g_call_count++;
    return VERSION_STRING;
}

MATHLIB_API int mathlib_version_major(void) {
    return VERSION_MAJOR;
}

MATHLIB_API int mathlib_version_minor(void) {
    return VERSION_MINOR;
}

// Basic math operations
MATHLIB_API int mathlib_add(int a, int b) {
    g_call_count++;
    // Check for overflow
    if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) {
        return 0; // Overflow
    }
    return a + b;
}

MATHLIB_API int mathlib_subtract(int a, int b) {
    g_call_count++;
    // Check for overflow
    if ((b < 0 && a > INT_MAX + b) || (b > 0 && a < INT_MIN + b)) {
        return 0; // Overflow
    }
    return a - b;
}

MATHLIB_API int mathlib_multiply(int a, int b) {
    g_call_count++;
    // Simple overflow check
    if (a != 0 && abs(b) > INT_MAX / abs(a)) {
        return 0; // Overflow
    }
    return a * b;
}

MATHLIB_API double mathlib_divide(double a, double b) {
    g_call_count++;
    if (b == 0.0) {
        return 0.0; // Division by zero
    }
    return a / b;
}

// Advanced operations
MATHLIB_API long long mathlib_factorial(int n) {
    g_call_count++;
    if (n < 0) return -1;
    if (n == 0 || n == 1) return 1;
    
    long long result = 1;
    for (int i = 2; i <= n && i <= 20; i++) { // Limit to prevent overflow
        result *= i;
    }
    return result;
}

MATHLIB_API int mathlib_fibonacci(int n) {
    g_call_count++;
    if (n <= 0) return 0;
    if (n == 1) return 1;
    
    int a = 0, b = 1, temp;
    for (int i = 2; i <= n; i++) {
        temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

MATHLIB_API int mathlib_gcd(int a, int b) {
    g_call_count++;
    a = abs(a);
    b = abs(b);
    
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

MATHLIB_API int mathlib_is_prime(int n) {
    g_call_count++;
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return 0;
        }
    }
    return 1;
}

// Array operations
MATHLIB_API int mathlib_array_sum(const int* array, int size) {
    g_call_count++;
    if (!array || size <= 0) return 0;
    
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += array[i];
    }
    return sum;
}

MATHLIB_API double mathlib_array_average(const int* array, int size) {
    g_call_count++;
    if (!array || size <= 0) return 0.0;
    
    return (double)mathlib_array_sum(array, size) / size;
}

MATHLIB_API int mathlib_array_max(const int* array, int size) {
    g_call_count++;
    if (!array || size <= 0) return INT_MIN;
    
    int max = array[0];
    for (int i = 1; i < size; i++) {
        if (array[i] > max) {
            max = array[i];
        }
    }
    return max;
}

MATHLIB_API int mathlib_array_min(const int* array, int size) {
    g_call_count++;
    if (!array || size <= 0) return INT_MAX;
    
    int min = array[0];
    for (int i = 1; i < size; i++) {
        if (array[i] < min) {
            min = array[i];
        }
    }
    return min;
}

// Callback function
MATHLIB_API int mathlib_apply_operation(int value, mathlib_callback operation) {
    g_call_count++;
    if (!operation) return value;
    return operation(value);
}

// Global state functions
MATHLIB_API void mathlib_set_global_seed(unsigned int seed) {
    g_call_count++;
    g_random_seed = seed;
}

MATHLIB_API unsigned int mathlib_get_global_seed(void) {
    g_call_count++;
    return g_random_seed;
}

MATHLIB_API int mathlib_random(void) {
    g_call_count++;
    // Simple LCG (Linear Congruential Generator)
    g_random_seed = (g_random_seed * 1103515245 + 12345) & 0x7fffffff;
    return (int)(g_random_seed % RAND_MAX);
}

// Point distance calculation
MATHLIB_API double mathlib_point_distance(const MathPoint* p1, const MathPoint* p2) {
    g_call_count++;
    if (!p1 || !p2) return -1.0;
    
    double dx = p2->x - p1->x;
    double dy = p2->y - p1->y;
    return sqrt(dx * dx + dy * dy);
}

// Hidden/internal function (not in header)
int mathlib_get_call_count(void) {
    return g_call_count;
}