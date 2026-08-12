#include <stdint.h>

/* A price-time priority matching engine over two sorted flat arrays.  An
 * incoming order walks the opposing side while it crosses, partially filling
 * resting quantities and compacting the book -- array mutation driven by a
 * two-sided comparison. */

#define BOOK_MAX 8

__attribute__((noinline)) int32_t
match_order(int32_t *resting_prices, int32_t *resting_quantities,
            int32_t resting_count, int32_t incoming_price,
            int32_t incoming_quantity, int32_t is_buy, int32_t *filled_out) {
    int32_t filled = 0;
    int32_t level = 0;
    int32_t survivors = 0;
    int32_t index;
    if (resting_prices == 0 || resting_quantities == 0 || filled_out == 0 ||
        resting_count < 0 || resting_count > BOOK_MAX ||
        incoming_quantity < 0 || incoming_quantity > 1000000) {
        return -1;
    }
    while (level < resting_count && filled < incoming_quantity) {
        int32_t price = resting_prices[level];
        int32_t available = resting_quantities[level];
        int32_t crosses = is_buy ? (price <= incoming_price)
                                 : (price >= incoming_price);
        int32_t take;
        if (!crosses || available <= 0) {
            break;
        }
        take = incoming_quantity - filled;
        if (take > available) {
            take = available;
        }
        resting_quantities[level] = available - take;
        filled += take;
        level += 1;
    }
    for (index = 0; index < resting_count; ++index) {
        if (resting_quantities[index] > 0) {
            resting_prices[survivors] = resting_prices[index];
            resting_quantities[survivors] = resting_quantities[index];
            survivors += 1;
        }
    }
    for (index = survivors; index < resting_count; ++index) {
        resting_prices[index] = 0;
        resting_quantities[index] = 0;
    }
    *filled_out = filled;
    return survivors;
}
