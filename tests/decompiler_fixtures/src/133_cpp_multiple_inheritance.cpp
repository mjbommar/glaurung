/* 133_cpp_multiple_inheritance.cpp
 *
 * Multiple inheritance forces `this`-pointer adjustment: a Derived* converted
 * to its second base points partway into the object, so the compiler emits
 * thunks that add a fixed offset before jumping to the real body. Casting
 * between base pointers therefore changes the numeric address, and comparing
 * two base pointers of one object is NOT a plain address comparison.
 */
#include <stdint.h>

namespace {

class Readable {
public:
    virtual ~Readable() {}
    virtual int32_t read(int32_t index) const { return index; }
};

class Writable {
public:
    virtual ~Writable() {}
    virtual int32_t write(int32_t index, int32_t value) { return index + value; }
    virtual int32_t flushed() const { return 0; }
};

class File : public Readable, public Writable {
public:
    int32_t stored;
    File() : stored(0) {}
    int32_t read(int32_t index) const override { return index * 2 + stored; }
    int32_t write(int32_t index, int32_t value) override {
        stored = index ^ value;
        return stored;
    }
    int32_t flushed() const override { return stored + 1; }
};

}  // namespace

extern "C" int32_t cpp_mi_dispatch(int32_t index, int32_t value) {
    File file;
    Readable *readable = &file;
    Writable *writable = &file; /* adjusted: not the same address */
    int32_t written = writable->write(index, value);
    int32_t got = readable->read(index);
    return written * 100 + got;
}

extern "C" int32_t cpp_mi_pointer_adjustment(int32_t seed) {
    File file;
    file.stored = seed;
    const Readable *readable = &file;
    const Writable *writable = &file;
    /* The two base subobjects live at different offsets, so the raw addresses
     * differ even though both denote the same complete object. */
    const void *first = static_cast<const void *>(readable);
    const void *second = static_cast<const void *>(writable);
    return (first != second) ? 1 : 0;
}

extern "C" int32_t cpp_mi_cross_cast(int32_t index, int32_t value) {
    File file;
    Writable *writable = &file;
    /* Cross-cast through the complete object, then dispatch on the far base. */
    File *complete = static_cast<File *>(writable);
    Readable *readable = complete;
    writable->write(index, value);
    return readable->read(index) + writable->flushed();
}
