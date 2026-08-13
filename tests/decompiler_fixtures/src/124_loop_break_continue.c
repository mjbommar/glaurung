#include <stdint.h>

/* break and continue bind to the innermost enclosing loop or switch. A break
 * inside a switch inside a loop leaves the switch, not the loop -- the single
 * most common source of a mis-structured recovery. */

__attribute__((noinline)) int32_t
break_binds_to_switch(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        switch (values[index] & 3) {
        case 0:
            total += 1;
            break; /* leaves the switch; the loop continues */
        case 1:
            total += 10;
            continue; /* this one does leave the iteration */
        case 2:
            total += 100;
            break;
        default:
            total += 1000;
            break;
        }
        total += 1; /* reached for cases 0, 2, 3 but not 1 */
    }
    return total;
}

__attribute__((noinline)) int32_t
nested_loop_early_exit(const int32_t *grid, int32_t rows, int32_t columns,
                       int32_t needle) {
    int32_t row;
    int32_t column;
    int32_t visited = 0;
    if (grid == 0 || rows < 0 || rows > 4 || columns < 0 || columns > 4) {
        return -1;
    }
    for (row = 0; row < rows; ++row) {
        for (column = 0; column < columns; ++column) {
            visited += 1;
            if (grid[row * columns + column] == needle) {
                goto found; /* the only clean way out of two loops */
            }
        }
    }
    return -visited;
found:
    return visited;
}

__attribute__((noinline)) int32_t
continue_in_do_while(int32_t limit) {
    int32_t index = 0;
    int32_t total = 0;
    if (limit < 0 || limit > 16) {
        return -1;
    }
    do {
        index += 1;
        if ((index & 1) == 0) {
            continue; /* jumps to the controlling expression, not the top */
        }
        total += index;
    } while (index < limit);
    return total;
}
