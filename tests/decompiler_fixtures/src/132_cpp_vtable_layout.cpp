/* 132_cpp_vtable_layout.cpp
 *
 * Single-inheritance virtual dispatch. Each polymorphic class gets a vtable in
 * read-only data; an object's first word points at it, and a virtual call is a
 * load of that pointer followed by an indirect call through a fixed slot index.
 * Overriding replaces the slot, so the same call site reaches different bodies
 * with no branch anywhere in the caller.
 *
 * No STL: the target is the generated dispatch machinery, not library code.
 */
#include <stdint.h>

namespace {

class Shape {
public:
    virtual ~Shape() {}
    virtual int32_t area(int32_t a, int32_t b) const = 0;
    virtual int32_t perimeter(int32_t a, int32_t b) const {
        return 2 * (a + b);
    }
    virtual int32_t tag() const { return 0; }
};

class Rect : public Shape {
public:
    int32_t area(int32_t a, int32_t b) const override { return a * b; }
    int32_t tag() const override { return 1; }
};

class Square : public Rect {
public:
    int32_t area(int32_t a, int32_t) const override { return a * a; }
    /* perimeter() is NOT overridden: the slot still points at Shape's body. */
    int32_t tag() const override { return 2; }
};

class Triangle : public Shape {
public:
    int32_t area(int32_t a, int32_t b) const override { return (a * b) / 2; }
    int32_t perimeter(int32_t a, int32_t b) const override { return a + b + a; }
    int32_t tag() const override { return 3; }
};

}  // namespace

extern "C" int32_t cpp_vtable_area(int32_t which, int32_t a, int32_t b) {
    Rect rect;
    Square square;
    Triangle triangle;
    const Shape *shape;
    switch (which & 3) {
    case 0: shape = &rect; break;
    case 1: shape = &square; break;
    case 2: shape = &triangle; break;
    default: shape = &rect; break;
    }
    return shape->area(a, b);
}

extern "C" int32_t cpp_vtable_inherited_slot(int32_t which, int32_t a,
                                             int32_t b) {
    Rect rect;
    Square square;
    Triangle triangle;
    const Shape *shape;
    switch (which & 3) {
    case 0: shape = &rect; break;
    case 1: shape = &square; break;
    default: shape = &triangle; break;
    }
    /* Square inherits Shape::perimeter through Rect without overriding it. */
    return shape->perimeter(a, b) * 10 + shape->tag();
}

extern "C" int32_t cpp_vtable_devirtualized(int32_t a, int32_t b) {
    Square square;
    /* The dynamic type is known here, so the call may be devirtualized and
     * inlined at -O2 while remaining an indirect call at -O0. */
    return square.area(a, b) + square.perimeter(a, b);
}
