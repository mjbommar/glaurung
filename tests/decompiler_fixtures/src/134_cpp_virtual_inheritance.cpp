/* 134_cpp_virtual_inheritance.cpp
 *
 * Virtual inheritance: the shared base appears once, reached through a virtual
 * base offset stored in the vtable rather than at a compile-time-fixed
 * displacement. Member access on the shared base is therefore an extra indirect
 * load, and construction order is determined by the most-derived class.
 */
#include <stdint.h>

namespace {

class Base {
public:
    int32_t value;
    Base() : value(1) {}
    virtual ~Base() {}
    virtual int32_t identify() const { return 1; }
};

class Left : public virtual Base {
public:
    int32_t left_mark;
    Left() : left_mark(2) {}
    int32_t identify() const override { return 2; }
};

class Right : public virtual Base {
public:
    int32_t right_mark;
    Right() : right_mark(3) {}
    int32_t identify() const override { return 3; }
};

class Diamond : public Left, public Right {
public:
    int32_t diamond_mark;
    Diamond() : diamond_mark(4) {}
    int32_t identify() const override { return 4; }
};

}  // namespace

extern "C" int32_t cpp_virtual_base_is_shared(int32_t seed) {
    Diamond diamond;
    diamond.value = seed;
    /* One shared Base: both paths observe the same object. */
    const Left *left = &diamond;
    const Right *right = &diamond;
    return (left->value == right->value) ? left->value : -1;
}

extern "C" int32_t cpp_virtual_base_offset(int32_t seed) {
    Diamond diamond;
    diamond.value = seed;
    diamond.left_mark = seed + 1;
    diamond.right_mark = seed + 2;
    diamond.diamond_mark = seed + 3;
    /* Reaching `value` from a Left* needs the virtual base offset from the
     * vtable; reaching `left_mark` does not. */
    const Left *left = &diamond;
    return left->value * 1000 + left->left_mark;
}

extern "C" int32_t cpp_virtual_final_overrider(int32_t which) {
    Diamond diamond;
    Left left;
    Right right;
    const Base *base;
    switch (which & 3) {
    case 0: base = &diamond; break;
    case 1: base = &left; break;
    default: base = &right; break;
    }
    return base->identify();
}
