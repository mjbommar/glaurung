/* Independent textbook-example checks for the curriculum source corpus.
 *
 * The round-trip differential proves that recovered code matches the original
 * binary.  This driver separately proves that the original programs implement
 * the algorithms claimed by the catalog, preventing two equally wrong programs
 * from looking like a successful differential.
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#include "src/15_binary_search_tree.c"
#include "src/16_red_black_tree.c"
#include "src/17_hash_table.c"
#include "src/18_binary_heap.c"
#include "src/19_disjoint_set.c"
#include "src/20_graph_bfs.c"
#include "src/21_graph_dfs.c"
#include "src/22_dijkstra.c"
#include "src/23_topological_sort.c"
#include "src/24_merge_sort.c"
#include "src/25_kmp_search.c"
#include "src/26_sparse_matrix.c"
#include "src/27_newton_raphson.c"
#include "src/28_euler_ode.c"
#include "src/29_polynomial.c"
#include "src/30_finite_difference.c"
#include "src/31_edit_distance.c"
#include "src/32_longest_common_subsequence.c"
#include "src/33_knapsack.c"
#include "src/34_coin_change.c"
#include "src/35_matrix_chain.c"
#include "src/36_quicksort.c"
#include "src/37_heapsort.c"
#include "src/38_insertion_shell_sort.c"
#include "src/39_counting_radix_sort.c"
#include "src/40_quickselect.c"
#include "src/41_tokenizer.c"
#include "src/42_rpn_evaluator.c"
#include "src/43_base64.c"
#include "src/44_run_length.c"
#include "src/45_string_algorithms.c"
#include "src/46_bitset.c"
#include "src/47_huffman.c"
#include "src/48_gray_code.c"
#include "src/49_crc32.c"
#include "src/50_varint.c"
#include "src/51_rc4.c"
#include "src/52_hash_functions.c"
#include "src/53_pseudorandom.c"
#include "src/54_sha256_block.c"
#include "src/55_modular_arithmetic.c"
#include "src/56_sieve.c"
#include "src/57_bignum.c"
#include "src/58_rational.c"
#include "src/59_combinatorics.c"
#include "src/60_integer_matrix.c"
#include "src/61_fixed_point.c"
#include "src/62_gaussian_elimination.c"
#include "src/63_numerical_integration.c"
#include "src/64_root_finding.c"
#include "src/65_projectile_motion.c"
#include "src/66_orbital_step.c"
#include "src/67_elastic_collision.c"
#include "src/68_thermodynamics.c"
#include "src/69_molar_mass.c"
#include "src/70_reaction_balance.c"
#include "src/71_compound_interest.c"
#include "src/72_loan_amortization.c"
#include "src/73_present_value.c"
#include "src/74_moving_statistics.c"
#include "src/75_order_book.c"
#include "src/76_portfolio_rebalance.c"
#include "src/77_lru_cache.c"
#include "src/78_ring_buffer.c"
#include "src/79_segment_tree.c"
#include "src/80_trie.c"

#define CHECK(condition, code)                                                \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "curriculum oracle failed at check %d\n", code); \
            return code;                                                       \
        }                                                                      \
    } while (0)

static int same_i32(const int32_t *left, const int32_t *right, int32_t n) {
    int32_t i;
    for (i = 0; i < n; ++i) {
        if (left[i] != right[i]) {
            return 0;
        }
    }
    return 1;
}

static int near_q16(int32_t observed, int32_t expected, int32_t tolerance) {
    int32_t difference = observed - expected;
    if (difference < 0) {
        difference = -difference;
    }
    return difference <= tolerance;
}

/* Dynamic programming, sorting, and selection. */
static int check_algorithms(void) {
    uint8_t kitten[] = {'k', 'i', 't', 't', 'e', 'n'};
    uint8_t sitting[] = {'s', 'i', 't', 't', 'i', 'n', 'g'};
    uint8_t karolin[] = {'k', 'a', 'r', 'o', 'l', 'i', 'n'};
    uint8_t kathrin[] = {'k', 'a', 't', 'h', 'r', 'i', 'n'};
    uint8_t lcs_left[] = {'A', 'B', 'C', 'B', 'D', 'A', 'B'};
    uint8_t lcs_right[] = {'B', 'D', 'C', 'A', 'B', 'A'};
    uint8_t recovered[16] = {0};
    int32_t knap_weights[] = {1, 3, 4, 5};
    int32_t knap_values[] = {1, 4, 5, 7};
    int32_t unbounded_weights[] = {1, 3, 4};
    int32_t unbounded_values[] = {10, 40, 50};
    int32_t coins[] = {1, 3, 4};
    int32_t coins2[] = {1, 2, 5};
    int32_t chain[] = {10, 30, 5, 60};
    int32_t data[8];
    uint8_t bytes[6] = {5, 1, 4, 1, 5, 9};
    uint32_t wide[6] = {900u, 3u, 77u, 1u, 65536u, 42u};
    int32_t index;

    /* Levenshtein's canonical pair is distance 3. */
    CHECK(edit_distance(kitten, 6, sitting, 7) == 3, 100);
    CHECK(edit_distance(kitten, 6, kitten, 6) == 0, 101);
    CHECK(hamming_distance(karolin, kathrin, 7) == 3, 102);

    /* LCS("ABCBDAB","BDCABA") = "BCBA", length 4. */
    CHECK(lcs_length(lcs_left, 7, lcs_right, 6) == 4, 103);
    CHECK(lcs_recover(lcs_left, 7, lcs_right, 6, recovered) == 4, 104);
    CHECK(recovered[0] == 'B' && recovered[3] == 'A', 105);

    CHECK(knapsack_best_value(knap_weights, knap_values, 4, 7) == 9, 106);
    CHECK(unbounded_knapsack(unbounded_weights, unbounded_values, 3, 8) == 100, 107);

    CHECK(min_coins(coins, 3, 6) == 2, 108);
    CHECK(min_coins(coins, 3, 0) == 0, 109);
    CHECK(count_change(coins2, 3, 5) == 4u, 110);

    /* The textbook 10x30, 30x5, 5x60 chain costs 4500 scalar multiplies. */
    CHECK(matrix_chain_cost(chain, 3) == 4500, 111);

    for (index = 0; index < 8; ++index) {
        data[index] = (int32_t)((11 * index + 5) % 13) - 6;
    }
    CHECK(quicksort_i32(data, 8) == 8, 112);
    CHECK(data[0] <= data[1] && data[6] <= data[7], 113);

    for (index = 0; index < 8; ++index) {
        data[index] = (int32_t)((7 * index + 3) % 11) - 5;
    }
    CHECK(heapsort_i32(data, 8) == 8, 114);
    CHECK(data[0] <= data[7], 115);

    for (index = 0; index < 8; ++index) {
        data[index] = 8 - index;
    }
    CHECK(insertion_sort_i32(data, 8) == 8, 116);
    CHECK(data[0] == 1 && data[7] == 8, 117);

    for (index = 0; index < 8; ++index) {
        data[index] = 8 - index;
    }
    CHECK(shell_sort_i32(data, 8) == 8, 118);
    CHECK(data[0] == 1 && data[7] == 8, 119);

    CHECK(counting_sort_u8(bytes, 6) == 6, 120);
    CHECK(bytes[0] == 1 && bytes[1] == 1 && bytes[5] == 9, 121);
    CHECK(radix_sort_u32(wide, 6) == 6, 122);
    CHECK(wide[0] == 1u && wide[5] == 65536u, 123);

    for (index = 0; index < 8; ++index) {
        data[index] = (int32_t)((5 * index + 2) % 9);
    }
    CHECK(quickselect_kth(data, 8, 0) == 0, 124);
    CHECK(median_of_three(3, 1, 2) == 2, 125);
    return 0;
}

/* Strings, parsing, bit manipulation, and hashing. */
static int check_encoding(void) {
    uint8_t sentence[] = {'a', 'b', ' ', '1', '2'};
    uint8_t rpn_tokens[] = {'#', '#', '+'};
    int32_t rpn_operands[] = {2, 3, 0};
    uint8_t man[] = {'M', 'a', 'n'};
    uint8_t twfu[] = {'T', 'W', 'F', 'u'};
    uint8_t runs[] = {'a', 'a', 'a', 'b', 'b', 'c'};
    uint8_t signed_text[] = {'-', '1', '2', '3'};
    uint8_t abba[] = {'a', 'b', 'b', 'a'};
    uint8_t digits[] = {'9', '9', '9'};
    uint8_t check_string[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint8_t encoded[16] = {0};
    uint8_t decoded[16] = {0};
    uint32_t words[2] = {0x0000000Fu, 0x00000101u};
    int32_t frequencies[] = {5, 9, 12, 13, 16, 45};
    int32_t lengths[8] = {0};
    uint32_t sequence[4] = {0};
    uint32_t varint_value = 0;
    uint8_t three_hundred[] = {0xACu, 0x02u};
    int32_t words_seen = 0;
    int32_t numbers_seen = 0;
    int32_t result = 0;
    int32_t parsed = 0;

    CHECK(tokenize(sentence, 5, &words_seen, &numbers_seen) == 2, 130);
    CHECK(words_seen == 1 && numbers_seen == 1, 131);

    CHECK(rpn_evaluate(rpn_tokens, rpn_operands, 3, &result) == 1, 132);
    CHECK(result == 5, 133);

    /* RFC 4648: "Man" encodes to "TWFu". */
    CHECK(base64_encode(man, 3, encoded) == 4, 134);
    CHECK(encoded[0] == 'T' && encoded[1] == 'W' && encoded[2] == 'F' &&
              encoded[3] == 'u',
          135);
    CHECK(base64_decode(twfu, 4, decoded) == 3, 136);
    CHECK(decoded[0] == 'M' && decoded[1] == 'a' && decoded[2] == 'n', 137);

    CHECK(rle_encode(runs, 6, encoded, 16) == 6, 138);
    CHECK(encoded[0] == 3 && encoded[1] == 'a' && encoded[4] == 1, 139);
    CHECK(rle_decode(encoded, 6, decoded, 16) == 6, 140);
    CHECK(decoded[0] == 'a' && decoded[5] == 'c', 141);

    CHECK(parse_decimal(signed_text, 4, &parsed) == 3, 142);
    CHECK(parsed == -123, 143);
    CHECK(parse_decimal(digits, 3, &parsed) == 3 && parsed == 999, 144);
    CHECK(format_decimal(-4096, encoded, 8) == 5, 145);
    CHECK(encoded[0] == '-' && encoded[4] == '6', 146);
    CHECK(is_palindrome(abba, 4) == 1, 147);
    CHECK(is_palindrome(man, 3) == 0, 148);

    CHECK(bitset_population(words, 2) == 6u, 149);
    CHECK(bitset_rank(words, 2, 4) == 4, 150);
    CHECK(bitset_select(words, 2, 0) == 0, 151);
    CHECK(bitset_select(words, 2, 4) == 32, 152);

    /* Huffman's canonical example: lengths 4,4,3,3,3,1 summing to 18, and a
     * Kraft sum of exactly one. */
    CHECK(huffman_code_lengths(frequencies, 6, lengths) == 18, 153);
    CHECK(lengths[0] == 4 && lengths[2] == 3 && lengths[5] == 1, 154);
    CHECK(kraft_sum_q16(lengths, 6) == 65536u, 155);

    CHECK(binary_to_gray(4u) == 6u, 156);
    CHECK(gray_to_binary(6u) == 4u, 157);
    CHECK(gray_to_binary(binary_to_gray(12345u)) == 12345u, 158);
    CHECK(reverse_bits32(1u) == 0x80000000u, 159);
    CHECK(gray_sequence(sequence, 4) == 4, 160);
    CHECK(sequence[3] == 2u, 161);

    /* The published CRC-32 check value for "123456789". */
    CHECK(crc32_bitwise(check_string, 9) == 0xCBF43926u, 162);
    CHECK(crc32_table_driven(check_string, 9) == 0xCBF43926u, 163);
    CHECK(internet_checksum(check_string, 9) != 0u, 164);

    CHECK(zigzag_encode(-1) == 1u, 165);
    CHECK(zigzag_encode(1) == 2u, 166);
    CHECK(zigzag_decode(zigzag_encode(-12345)) == -12345, 167);
    CHECK(varint_encode(300u, encoded, 16) == 2, 168);
    CHECK(encoded[0] == 0xACu && encoded[1] == 0x02u, 169);
    CHECK(varint_decode(three_hundred, 2, &varint_value) == 2, 170);
    CHECK(varint_value == 300u, 171);

    /* FNV-1a offset basis, and the RC4 keystream for key "Key" folded by the
     * same rolling checksum the fixture computes. */
    CHECK(fnv1a_32(man, 0) == 2166136261u, 172);
    CHECK(djb2_xor(man, 0) == 5381u, 173);
    CHECK(murmur3_finalize(0u) == 0u, 174);
    return 0;
}

/* Number theory, wide arithmetic, and linear algebra. */
static int check_number_theory(void) {
    uint8_t rc4_key[] = {'K', 'e', 'y'};
    uint32_t sha_block[16] = {0};
    uint32_t sha_state[8] = {0};
    uint8_t flags[64] = {0};
    int32_t factors[8] = {0};
    uint32_t left_limbs[2] = {65535u, 1u};
    uint32_t right_limbs[2] = {1u, 0u};
    uint32_t limb_output[8] = {0};
    uint32_t pascal[13] = {0};
    int32_t identity[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    int32_t sample[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    int32_t product[16] = {0};
    int32_t transposed[16] = {0};
    int32_t singular[9] = {1, 2, 3, 4, 5, 6, 7, 8, 10};
    int32_t numerator = 0;
    int32_t denominator = 0;
    int32_t bezout_x = 0;
    int32_t bezout_y = 0;

    /* RC4 with key "Key" has published keystream EB 9F 77 81; the fixture folds
     * it with checksum = checksum * 33 + byte. */
    CHECK(rc4_keystream_checksum(rc4_key, 3, 4) == 8622402u, 180);

    /* One compression of the padded empty message must reproduce the published
     * SHA-256 of "". */
    sha_block[0] = 0x80000000u;
    CHECK(sha256_compress_block(sha_block, sha_state) != 0u, 181);
    CHECK(sha_state[0] == 0xE3B0C442u, 182);
    CHECK(sha_state[1] == 0x98FC1C14u, 183);
    CHECK(sha_state[7] == 0x7852B855u, 184);

    CHECK(gcd_i32(48, 18) == 6, 185);
    CHECK(gcd_i32(17, 0) == 17, 186);
    /* gcd(240,46) = 2 with Bezout coefficients -9 and 47. */
    CHECK(extended_gcd(240, 46, &bezout_x, &bezout_y) == 2, 187);
    CHECK(bezout_x == -9 && bezout_y == 47, 188);
    CHECK(mod_pow(2u, 10u, 1000u) == 24u, 189);

    /* Eleven primes below 32. */
    CHECK(sieve_primes(flags, 32) == 11, 190);
    CHECK(flags[2] == 1 && flags[31] == 1 && flags[9] == 0, 191);
    CHECK(factorize(360, factors, 8) == 6, 192);
    CHECK(factors[0] == 2 && factors[3] == 3 && factors[5] == 5, 193);

    /* 65535 + 1 carries into the next base-65536 limb. */
    CHECK(bignum_add(left_limbs, 2, right_limbs, 2, limb_output, 8) == 2, 194);
    CHECK(limb_output[0] == 0u && limb_output[1] == 2u, 195);
    CHECK(bignum_mul_small(left_limbs, 1, 2u, limb_output, 8) == 2, 196);
    CHECK(limb_output[0] == 65534u && limb_output[1] == 1u, 197);

    CHECK(rational_add(1, 2, 1, 3, &numerator, &denominator) == 1, 198);
    CHECK(numerator == 5 && denominator == 6, 199);
    CHECK(rational_compare(1, 2, 1, 3) == 1, 200);
    CHECK(rational_compare(2, 4, 1, 2) == 0, 201);

    CHECK(pascal_row(4, pascal, 13) == 5, 202);
    CHECK(pascal[0] == 1u && pascal[1] == 4u && pascal[2] == 6u, 203);
    CHECK(binomial(10, 3) == 120u, 204);
    CHECK(catalan(5) == 42u, 205);

    CHECK(matrix_multiply(identity, sample, product, 4) == 16, 206);
    CHECK(same_i32(product, sample, 16), 207);
    CHECK(matrix_transpose(sample, transposed, 4) == 16, 208);
    CHECK(transposed[1] == sample[4], 209);
    CHECK(determinant3(singular) == -3, 210);
    return 0;
}

/* Fixed-point numerics, physics, chemistry, and finance. */
static int check_applied(void) {
    int32_t augmented[6] = {131072, 65536, 524288, 65536, 196608, 851968};
    int32_t solution[4] = {0};
    int32_t impact = 0;
    int32_t position_x = 65536;
    int32_t position_y = 0;
    int32_t velocity_x = 0;
    int32_t velocity_y = 65536;
    uint8_t water[] = {'H', '2', 'O'};
    uint8_t glucose[] = {'C', '6', 'H', '1', '2', 'O', '6'};
    uint8_t salt[] = {'N', 'a', 'C', 'l'};
    int32_t hydrogen[] = {2, 0};
    int32_t oxygen[] = {0, 2};
    int32_t water_atoms[] = {2, 1};
    int32_t absent[] = {0, 0};
    int32_t coefficients[4] = {0};
    int32_t interest[12] = {0};
    int32_t principal[12] = {0};
    int32_t cashflows[] = {-65536, 39322, 39322};
    int32_t series[4] = {65536, 65536, 65536, 65536};
    int32_t averages[4] = {0};
    int32_t book_prices[3] = {100, 101, 102};
    int32_t book_quantities[3] = {5, 5, 5};
    int32_t filled = 0;
    int32_t values[4] = {100, 100, 100, 100};
    int32_t targets[4] = {16384, 16384, 16384, 16384};
    int32_t trades[4] = {0};
    int32_t keys[4] = {0, 0, 0, 0};
    int32_t stamps[4] = {0, 0, 0, 0};
    int32_t evicted = 0;
    int32_t storage[8] = {0};
    uint32_t head = 0;
    uint32_t tail = 0;
    int32_t popped = 0;
    int32_t tree[16] = {0};
    int32_t leaves[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int32_t trie_children[96] = {0};
    uint8_t trie_terminal[24] = {0};
    int32_t trie_cursor = 1;
    uint8_t ab[] = {'a', 'b'};
    uint8_t abc[] = {'a', 'b', 'c'};
    int32_t rate;

    CHECK(fixed_multiply(131072, 196608) == 393216, 220);
    CHECK(fixed_divide(65536, 131072) == 32768, 221);
    CHECK(fixed_sqrt(262144) == 131072, 222);
    CHECK(fixed_lerp(0, 65536, 32768) == 32768, 223);

    /* 2x + y = 8, x + 3y = 13  ->  x = 2.2, y = 3.6 in Q16.16. */
    CHECK(gaussian_solve(augmented, 2, solution) == 2, 224);
    CHECK(near_q16(solution[0], 144179, 64), 225);
    CHECK(near_q16(solution[1], 235929, 64), 226);

    /* Integral of x^3 - 2x^2 + x on [0,1] is 1/12; Simpson is exact for a
     * cubic, so it must land closer than the trapezoid rule. */
    CHECK(near_q16(simpson_integrate(0, 65536, 8), 5461, 200), 227);
    CHECK(trapezoid_integrate(0, 65536, 8) != 0, 228);

    CHECK(near_q16(bisection_sqrt(262144, 64), 131072, 512), 229);
    CHECK(near_q16(newton_sqrt(262144, 64), 131072, 512), 230);

    /* Dropped from rest, height must fall and the impact must be recorded. */
    CHECK(projectile_step(655360, 0, 6553, 32, &impact) == 0, 231);
    CHECK(impact >= 0, 232);
    CHECK(kinetic_energy(131072, 131072) == 262144, 233);

    CHECK(orbital_step(&position_x, &position_y, &velocity_x, &velocity_y,
                       65536, 6553, 4) == 4, 234);
    CHECK(position_x != 65536 || position_y != 0, 235);

    /* Equal masses in an elastic collision exchange velocities exactly. */
    CHECK(elastic_velocity_a(65536, 65536, 131072, 0) == 0, 236);
    CHECK(elastic_velocity_a(65536, 65536, 0, 131072) == 131072, 237);
    CHECK(inelastic_velocity(65536, 65536, 131072, 0) == 65536, 238);
    CHECK(momentum_residual(65536, 65536, 131072, 0) == 0, 239);

    CHECK(ideal_gas_pressure(65536, 65536, 65536) > 0, 240);
    CHECK(newton_cooling(6553600, 0, 6553, 8) < 6553600, 241);
    CHECK(mixing_temperature(65536, 65536, 65536, 196608) == 131072, 242);

    /* H2O = 18.02, C6H12O6 = 180.18, NaCl = 58.44 (centi-amu). */
    CHECK(molar_mass_centi(water, 3) == 1802, 243);
    CHECK(molar_mass_centi(glucose, 7) == 18018, 244);
    CHECK(molar_mass_centi(salt, 4) == 5844, 245);

    /* 2 H2 + O2 -> 2 H2O. */
    CHECK(balance_reaction(hydrogen, oxygen, water_atoms, absent, 2,
                           coefficients) == 1,
          246);
    CHECK(coefficients[0] == 2 && coefficients[1] == 1 && coefficients[2] == 2,
          247);

    CHECK(compound_balance(65536, 6553, 0) == 65536, 248);
    CHECK(compound_balance(65536, 6553, 2) > 65536, 249);
    CHECK(annuity_future_value(65536, 0, 3) == 196608, 250);

    /* Interest plus principal must equal the payment in every period. */
    CHECK(amortization_schedule(655360, 6553, 131072, 6, interest,
                                principal) >= 0,
          251);
    CHECK(interest[0] + principal[0] == 131072, 252);
    CHECK(remaining_balance(655360, 6553, 131072, 6) >= 0, 253);

    CHECK(net_present_value(cashflows, 3, 0) == 13108, 254);
    rate = internal_rate_of_return(cashflows, 3);
    CHECK(rate > 0, 255);

    CHECK(simple_moving_average(series, 4, 1, averages) == 4, 256);
    CHECK(same_i32(averages, series, 4), 257);
    CHECK(exponential_moving_average(series, 4, 32768) == 65536, 258);
    CHECK(population_variance(series, 4) == 0, 259);

    CHECK(match_order(book_prices, book_quantities, 3, 101, 7, 1, &filled) == 2,
          260);
    CHECK(filled == 7, 261);

    CHECK(maximum_drift(values, targets, 4) == 0, 262);
    CHECK(rebalance_trades(values, targets, 4, trades) == 0, 263);

    CHECK(lru_access(keys, stamps, 4, 42, 1, &evicted) == 0, 264);
    CHECK(lru_access(keys, stamps, 4, 42, 2, &evicted) == 1, 265);

    CHECK(ring_push(storage, &head, &tail, 7) == 1, 266);
    CHECK(ring_occupancy(head, tail) == 1, 267);
    CHECK(ring_pop(storage, &head, &tail, &popped) == 1, 268);
    CHECK(popped == 7, 269);
    CHECK(ring_pop(storage, &head, &tail, &popped) == 0, 270);

    CHECK(segment_build(leaves, 8, tree) == 36, 271);
    CHECK(segment_range_sum(tree, 0, 4) == 10, 272);
    CHECK(segment_update(tree, 0, 11) == 46, 273);
    CHECK(segment_range_sum(tree, 0, 1) == 11, 274);

    CHECK(trie_insert(trie_children, trie_terminal, &trie_cursor, ab, 2) > 0,
          275);
    CHECK(trie_lookup(trie_children, trie_terminal, ab, 2) == 1, 276);
    CHECK(trie_lookup(trie_children, trie_terminal, ab, 1) == 0, 277);
    CHECK(trie_lookup(trie_children, trie_terminal, abc, 3) == 0, 278);
    return 0;
}

int main(void) {
    BstNode bst[] = {{8, 1, 2}, {4, 3, 4}, {12, 5, 6}, {2, -1, -1},
                     {6, -1, -1}, {10, -1, -1}, {14, -1, -1}};
    RbNode rb[] = {{8, 1, 2, 0}, {4, 3, 4, 1}, {12, 5, 6, 1},
                   {2, -1, -1, 0}, {6, -1, -1, 0}, {10, -1, -1, 0},
                   {14, -1, -1, 0}};
    int32_t keys[16];
    int32_t hash_values[16] = {0};
    int32_t heap[16] = {2, 5, 7, 12, 9, 11};
    int32_t removed[16] = {0};
    int32_t parent[16] = {0, 0, 2, 2, 4, 4};
    int32_t rank[16] = {1, 0, 1, 0, 1, 0};
    int32_t graph[] = {0, 1, 1, 0, 1, 0, 0, 1,
                       1, 0, 0, 1, 0, 1, 1, 0};
    int32_t dag[] = {0, 1, 1, 0, 0, 0, 0, 1,
                     0, 0, 0, 1, 0, 0, 0, 0};
    int32_t weights[] = {0, 4, 1, 0, 4, 0, 2, 5,
                         1, 2, 0, 8, 0, 5, 8, 0};
    int32_t output[16] = {0};
    int32_t expected[16] = {0};
    int32_t sortable[16] = {9, -3, 7, 7, 0, 12, -8, 1};
    uint8_t text[] = {1, 2, 1, 2, 1, 3};
    uint8_t pattern[] = {1, 2, 1, 3};
    int32_t row_offsets[] = {0, 2, 3, 5, 7};
    int32_t columns[] = {0, 3, 1, 0, 2, 1, 3};
    int32_t sparse_values[] = {10, 2, 3, 4, 5, 6, 7};
    int32_t vector[] = {1, 2, 3, 4};
    uint32_t sparse_output[16] = {0};
    uint32_t coefficients[] = {1, 2, 3, 4};
    int32_t heat_source[] = {0, 0, 100, 0, 0};
    int32_t heat_destination[16] = {0};
    int32_t i;

    CHECK(bst_search(bst, 7, 0, 10) == 5, 1);
    CHECK(bst_search(bst, 7, 0, 11) == -1, 2);
    CHECK(bst_inorder_checksum(bst, 7, 0) == 2746891832u, 3);

    CHECK(rb_validate(rb, 7, 0) == 1, 4);
    rb[0].color = 1;
    CHECK(rb_validate(rb, 7, 0) == 0, 5);

    for (i = 0; i < 16; ++i) {
        keys[i] = INT32_MIN;
    }
    CHECK(hash_insert(keys, hash_values, 8, 9, 90) == 1, 6);
    CHECK(hash_insert(keys, hash_values, 8, 17, 170) == 2, 7);
    CHECK(hash_lookup(keys, hash_values, 8, 17) == 170, 8);
    CHECK(hash_insert(keys, hash_values, 8, 25, 250) == 3, 9);

    CHECK(heap_push(heap, 6, 16, 3) == 7, 10);
    expected[0] = 2;
    expected[1] = 5;
    expected[2] = 3;
    expected[3] = 12;
    expected[4] = 9;
    expected[5] = 11;
    expected[6] = 7;
    CHECK(same_i32(heap, expected, 7), 11);
    CHECK(heap_pop(heap, 7, removed) == 6 && removed[0] == 2, 12);

    CHECK(dsu_find(parent, 6, 1) == 0, 13);
    CHECK(dsu_union(parent, rank, 6, 1, 5) == 0, 14);
    CHECK(parent[4] == 0 && rank[0] == 2, 15);

    expected[0] = 0;
    expected[1] = 1;
    expected[2] = 2;
    expected[3] = 3;
    CHECK(graph_bfs(graph, 4, 0, output) == 4 && same_i32(output, expected, 4),
          16);
    for (i = 0; i < 16; ++i) {
        output[i] = 0;
    }
    expected[0] = 0;
    expected[1] = 1;
    expected[2] = 3;
    expected[3] = 2;
    CHECK(graph_dfs(graph, 4, 0, output) == 4 && same_i32(output, expected, 4),
          17);

    CHECK(dijkstra_dense(weights, 4, 0, output) == 8, 18);
    expected[0] = 0;
    expected[1] = 3;
    expected[2] = 1;
    expected[3] = 8;
    CHECK(same_i32(output, expected, 4), 19);

    CHECK(topological_sort(dag, 4, output) == 4, 20);
    expected[0] = 0;
    expected[1] = 1;
    expected[2] = 2;
    expected[3] = 3;
    CHECK(same_i32(output, expected, 4), 21);

    CHECK(merge_sort_i32(sortable, 8) == 7, 22);
    expected[0] = -8;
    expected[1] = -3;
    expected[2] = 0;
    expected[3] = 1;
    expected[4] = 7;
    expected[5] = 7;
    expected[6] = 9;
    expected[7] = 12;
    CHECK(same_i32(sortable, expected, 8), 23);
    CHECK(kmp_search(text, 6, pattern, 4) == 2, 24);

    CHECK(csr_matvec(row_offsets, columns, sparse_values, vector, sparse_output,
                     4, 4, 7) == 542633u,
          25);
    CHECK(sparse_output[0] == 18u && sparse_output[1] == 6u &&
              sparse_output[2] == 19u && sparse_output[3] == 40u,
          26);
    CHECK(newton_isqrt(1000000u) == 1000u, 27);
    CHECK(newton_isqrt(UINT32_MAX) == 65535u, 28);
    CHECK(euler_decay_q16(65536, 16384, 2) == 36864, 29);
    CHECK(polynomial_eval_mod32(coefficients, 4, 5) == 586u, 30);
    CHECK(polynomial_derivative_mod32(coefficients, 4, 5) == 332u, 31);
    CHECK(heat_step_1d(heat_destination, heat_source, 5) == 953700u, 32);
    expected[0] = 0;
    expected[1] = 25;
    expected[2] = 50;
    expected[3] = 25;
    expected[4] = 0;
    CHECK(same_i32(heat_destination, expected, 5), 33);

    {
        int rc = check_algorithms();
        if (rc != 0) {
            return rc;
        }
        rc = check_encoding();
        if (rc != 0) {
            return rc;
        }
        rc = check_number_theory();
        if (rc != 0) {
            return rc;
        }
        rc = check_applied();
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}
