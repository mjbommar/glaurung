#define _GNU_SOURCE
#include <stdatomic.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Test acquisition provider: fixed storage, bounded snapshots, no allocator
 * metadata assumptions. This is compiled as an LD_PRELOAD library by the real
 * fixture gate; it is not linked into the samples. */

#define GOBJ_MAX_OBJECTS 1024
#define GOBJ_MAX_BYTES 256

enum {
    GOBJ_CREATE = 1,
    GOBJ_END = 2,
    GOBJ_SUMMARY = 3,
    GOBJ_WRITE = 4,
    GOBJ_PRE_WRITE = 5
};

struct gobj_header {
    unsigned char magic[8];
    uint8_t kind;
    uint8_t reserved[7];
    uint64_t provider_sequence;
    uint64_t os_tid;
    uint64_t object_id;
    uint64_t address;
    uint64_t caller_address;
    uint64_t caller_module_base;
    uint64_t object_size;
    uint64_t argument0;
    uint64_t argument1;
    uint32_t bytes_len;
    uint32_t dropped;
};

struct gobj_record {
    void *address;
    size_t size;
    uint64_t id;
    int used;
    int active;
};

extern void *__libc_calloc(size_t count, size_t size);
extern void __libc_free(void *pointer);
extern void *memcpy(void *destination, const void *source, size_t count);

static struct gobj_record records[GOBJ_MAX_OBJECTS];
static atomic_flag records_lock = ATOMIC_FLAG_INIT;
static uint64_t next_id = 1;
static _Atomic uint64_t next_provider_sequence = 1;
static uint32_t dropped_records;
static int output_fd = -1;
static uintptr_t main_module_base;
static uintptr_t main_module_start;
static uintptr_t main_module_end;

static int find_main_module(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0')
        return 0;
    uintptr_t start = UINTPTR_MAX;
    uintptr_t end = 0;
    for (ElfW(Half) index = 0; index < info->dlpi_phnum; index++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];
        if (header->p_type != PT_LOAD)
            continue;
        uintptr_t segment_start = (uintptr_t)info->dlpi_addr + header->p_vaddr;
        uintptr_t segment_end = segment_start + header->p_memsz;
        if (segment_start < start)
            start = segment_start;
        if (segment_end > end)
            end = segment_end;
    }
    if (start != UINTPTR_MAX && start < end) {
        main_module_base = (uintptr_t)info->dlpi_addr;
        main_module_start = start;
        main_module_end = end;
    }
    return 1;
}

static void lock_records(void) {
    while (atomic_flag_test_and_set_explicit(&records_lock, memory_order_acquire)) {
    }
}

static void unlock_records(void) {
    atomic_flag_clear_explicit(&records_lock, memory_order_release);
}

static void emit_record(uint8_t kind, uint64_t id, void *address, size_t size,
                        void *caller_address, uint64_t caller_module_base,
                        uint64_t argument0, uint64_t argument1,
                        const void *bytes, size_t bytes_len) {
    unsigned char buffer[sizeof(struct gobj_header) + GOBJ_MAX_BYTES];
    struct gobj_header header = {
        .magic = {'G', 'O', 'B', 'J', 'v', '4', 0, 0},
        .kind = kind,
        .provider_sequence = atomic_fetch_add_explicit(
            &next_provider_sequence, 1, memory_order_relaxed),
        .os_tid = (uint64_t)syscall(SYS_gettid),
        .object_id = id,
        .address = (uint64_t)(uintptr_t)address,
        .caller_address = (uint64_t)(uintptr_t)caller_address,
        .caller_module_base = caller_module_base,
        .object_size = (uint64_t)size,
        .argument0 = argument0,
        .argument1 = argument1,
        .bytes_len = (uint32_t)bytes_len,
        .dropped = dropped_records,
    };
    if (output_fd < 0 || bytes_len > GOBJ_MAX_BYTES)
        return;
    memcpy(buffer, &header, sizeof(header));
    if (bytes_len != 0)
        memcpy(buffer + sizeof(header), bytes, bytes_len);
    long written = syscall(SYS_write, output_fd, buffer, sizeof(header) + bytes_len);
    if (written != (long)(sizeof(header) + bytes_len))
        dropped_records++;
}

__attribute__((constructor)) static void initialize_provider(void) {
    dl_iterate_phdr(find_main_module, NULL);
    const char *text = getenv("GLAURUNG_HEAP_SNAPSHOT_FD");
    if (text != NULL)
        output_fd = atoi(text);
}

__attribute__((destructor)) static void finish_provider(void) {
    emit_record(GOBJ_SUMMARY, 0, NULL, 0, NULL, UINT64_MAX, 0, 0, NULL, 0);
}

void *calloc(size_t count, size_t size) {
    void *address = __libc_calloc(count, size);
    if (address == NULL || output_fd < 0)
        return address;
    size_t object_size;
    if (__builtin_mul_overflow(count, size, &object_size) || object_size == 0)
        return address;
    size_t snapshot_len = object_size < GOBJ_MAX_BYTES ? object_size : GOBJ_MAX_BYTES;

    lock_records();
    struct gobj_record *slot = NULL;
    for (size_t index = 0; index < GOBJ_MAX_OBJECTS; index++) {
        if (!records[index].used) {
            slot = &records[index];
            break;
        }
    }
    if (slot == NULL) {
        dropped_records++;
    } else {
        slot->address = address;
        slot->size = object_size;
        slot->id = next_id++;
        slot->used = 1;
        slot->active = 1;
        void *caller = __builtin_extract_return_addr(__builtin_return_address(0));
        uintptr_t caller_value = (uintptr_t)caller;
        uint64_t module_base =
            caller_value >= main_module_start && caller_value < main_module_end
                ? (uint64_t)main_module_base
                : UINT64_MAX;
        emit_record(GOBJ_CREATE, slot->id, address, object_size, caller,
                    module_base, (uint64_t)count, (uint64_t)size, address,
                    snapshot_len);
    }
    unlock_records();
    return address;
}

void free(void *address) {
    if (address != NULL && output_fd >= 0) {
        lock_records();
        for (size_t index = 0; index < GOBJ_MAX_OBJECTS; index++) {
            struct gobj_record *slot = &records[index];
            if (slot->active && slot->address == address) {
                size_t snapshot_len =
                    slot->size < GOBJ_MAX_BYTES ? slot->size : GOBJ_MAX_BYTES;
                emit_record(GOBJ_END, slot->id, address, slot->size, NULL,
                            UINT64_MAX, 0, 0, address, snapshot_len);
                slot->active = 0;
                break;
            }
        }
        unlock_records();
    }
    __libc_free(address);
}

__attribute__((optimize("no-tree-loop-distribute-patterns"))) void *
memset(void *destination, int value, size_t count) {
    struct gobj_record *matched = NULL;
    void *caller = NULL;
    uint64_t module_base = UINT64_MAX;
    size_t observed_len = count < GOBJ_MAX_BYTES ? count : GOBJ_MAX_BYTES;
    if (count != 0 && output_fd >= 0) {
        uintptr_t start = (uintptr_t)destination;
        lock_records();
        for (size_t index = 0; index < GOBJ_MAX_OBJECTS; index++) {
            struct gobj_record *slot = &records[index];
            uintptr_t object_start = (uintptr_t)slot->address;
            if (slot->used && start >= object_start &&
                start - object_start < slot->size) {
                matched = slot;
                caller = __builtin_extract_return_addr(__builtin_return_address(0));
                uintptr_t caller_value = (uintptr_t)caller;
                module_base =
                    caller_value >= main_module_start && caller_value < main_module_end
                        ? (uint64_t)main_module_base
                        : UINT64_MAX;
                if (slot->active) {
                    size_t snapshot_len =
                        slot->size < GOBJ_MAX_BYTES ? slot->size : GOBJ_MAX_BYTES;
                    emit_record(GOBJ_PRE_WRITE, slot->id, slot->address, slot->size,
                                caller, module_base,
                                (uint64_t)(unsigned char)value, (uint64_t)count,
                                slot->address, snapshot_len);
                }
                break;
            }
        }
        unlock_records();
    }
    volatile unsigned char *bytes = destination;
    for (size_t index = 0; index < count; index++)
        bytes[index] = (unsigned char)value;
    if (matched != NULL) {
        lock_records();
        emit_record(GOBJ_WRITE, matched->id, destination, count, caller,
                    module_base, (uint64_t)(unsigned char)value,
                    (uint64_t)count, destination, observed_len);
        unlock_records();
    }
    return destination;
}
