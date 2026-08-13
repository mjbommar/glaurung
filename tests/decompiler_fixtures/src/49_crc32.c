#include <stdint.h>

/* Table-driven CRC-32 (reflected, polynomial 0xEDB88320) alongside the
 * bitwise reference and an Internet checksum.  The table is built on the stack
 * each call, so a 256-entry initializer loop precedes the data loop. */

#define CRC_MAX 16

__attribute__((noinline)) uint32_t
crc32_bitwise(const uint8_t *data, int32_t length) {
    uint32_t crc = 0xFFFFFFFFu;
    int32_t index;
    int32_t bit;
    if (data == 0 || length < 0 || length > CRC_MAX) {
        return 0;
    }
    for (index = 0; index < length; ++index) {
        crc ^= (uint32_t)data[index];
        for (bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

__attribute__((noinline)) uint32_t
crc32_table_driven(const uint8_t *data, int32_t length) {
    uint32_t table[256];
    uint32_t crc = 0xFFFFFFFFu;
    uint32_t entry;
    int32_t index;
    int32_t bit;
    if (data == 0 || length < 0 || length > CRC_MAX) {
        return 0;
    }
    for (index = 0; index < 256; ++index) {
        entry = (uint32_t)index;
        for (bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)(-(int32_t)(entry & 1u));
            entry = (entry >> 1) ^ (0xEDB88320u & mask);
        }
        table[index] = entry;
    }
    for (index = 0; index < length; ++index) {
        crc = table[(crc ^ (uint32_t)data[index]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
}

__attribute__((noinline)) uint32_t
internet_checksum(const uint8_t *data, int32_t length) {
    uint32_t sum = 0;
    int32_t index;
    if (data == 0 || length < 0 || length > CRC_MAX) {
        return 0;
    }
    for (index = 0; index + 1 < length; index += 2) {
        sum += ((uint32_t)data[index] << 8) | (uint32_t)data[index + 1];
    }
    if ((length % 2) != 0) {
        sum += (uint32_t)data[length - 1] << 8;
    }
    while ((sum >> 16) != 0u) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (~sum) & 0xFFFFu;
}
