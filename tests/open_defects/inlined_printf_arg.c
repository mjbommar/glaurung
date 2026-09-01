#include <stdio.h>
/* Exactly hello.c's shape: the printf is INSIDE the function that gets
 * inlined, and the counter is a function-local static. */
static void inlined_printf_arg(void) {
  static int static_var = 0;
  static_var++;
  printf("called %d times\n", static_var);
}
int driver(int n) {
  inlined_printf_arg();
  if (n > 1) inlined_printf_arg();
  return n;
}
