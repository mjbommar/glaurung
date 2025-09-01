// mathlib.h - Header for sample shared library
#ifndef MATHLIB_H
#define MATHLIB_H

// Platform-specific export macros
#ifdef _WIN32
    #ifdef MATHLIB_EXPORTS
        #define MATHLIB_API __declspec(dllexport)
    #else
        #define MATHLIB_API __declspec(dllimport)
    #endif
#else
    #define MATHLIB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Version information
MATHLIB_API const char* mathlib_version(void);
MATHLIB_API int mathlib_version_major(void);
MATHLIB_API int mathlib_version_minor(void);

// Basic math operations
MATHLIB_API int mathlib_add(int a, int b);
MATHLIB_API int mathlib_subtract(int a, int b);
MATHLIB_API int mathlib_multiply(int a, int b);
MATHLIB_API double mathlib_divide(double a, double b);

// Advanced operations
MATHLIB_API long long mathlib_factorial(int n);
MATHLIB_API int mathlib_fibonacci(int n);
MATHLIB_API int mathlib_gcd(int a, int b);
MATHLIB_API int mathlib_is_prime(int n);

// Array operations
MATHLIB_API int mathlib_array_sum(const int* array, int size);
MATHLIB_API double mathlib_array_average(const int* array, int size);
MATHLIB_API int mathlib_array_max(const int* array, int size);
MATHLIB_API int mathlib_array_min(const int* array, int size);

// Callback function type
typedef int (*mathlib_callback)(int);

// Function that uses callback
MATHLIB_API int mathlib_apply_operation(int value, mathlib_callback operation);

// Global state functions (to test data sections)
MATHLIB_API void mathlib_set_global_seed(unsigned int seed);
MATHLIB_API unsigned int mathlib_get_global_seed(void);
MATHLIB_API int mathlib_random(void);

// Structure for testing
typedef struct {
    double x;
    double y;
} MathPoint;

MATHLIB_API double mathlib_point_distance(const MathPoint* p1, const MathPoint* p2);

#ifdef __cplusplus
}
#endif

#endif // MATHLIB_H