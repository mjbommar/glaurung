#include <stdint.h>

/* Reverse-Polish evaluation over an explicit operand stack.  Operators arrive
 * as bytes and dispatch through a switch; division guards zero and the
 * INT32_MIN / -1 overflow case, which is a real correctness trap. */

#define RPN_MAX 16

__attribute__((noinline)) int32_t
rpn_evaluate(const uint8_t *tokens, const int32_t *operands, int32_t length,
             int32_t *result) {
    int32_t stack[RPN_MAX];
    int32_t depth = 0;
    int32_t index;
    if (tokens == 0 || operands == 0 || result == 0 || length < 0 ||
        length > RPN_MAX) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        uint8_t token = tokens[index];
        if (token == (uint8_t)'#') {
            if (depth >= RPN_MAX) {
                return -2;
            }
            stack[depth] = operands[index];
            depth += 1;
            continue;
        }
        if (depth < 2) {
            return -3;
        }
        {
            int32_t right = stack[depth - 1];
            int32_t left = stack[depth - 2];
            int32_t value;
            depth -= 2;
            switch (token) {
            case '+':
                value = (int32_t)((uint32_t)left + (uint32_t)right);
                break;
            case '-':
                value = (int32_t)((uint32_t)left - (uint32_t)right);
                break;
            case '*':
                value = (int32_t)((uint32_t)left * (uint32_t)right);
                break;
            case '/':
                if (right == 0 || (left == (-2147483647 - 1) && right == -1)) {
                    return -4;
                }
                value = left / right;
                break;
            default:
                return -5;
            }
            stack[depth] = value;
            depth += 1;
        }
    }
    if (depth != 1) {
        return -6;
    }
    *result = stack[0];
    return depth;
}
