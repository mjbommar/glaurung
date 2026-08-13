/* 135_cpp_rtti.cpp
 *
 * RTTI: `dynamic_cast` consults a type_info record reachable from the vtable and
 * walks the inheritance graph at runtime, returning null on failure. `typeid`
 * compares those records. Neither is expressible as a static offset, so both are
 * real calls into the runtime (__dynamic_cast) that a decompiler must not fold
 * into a constant.
 */
#include <stdint.h>
#include <typeinfo>

namespace {

class Animal {
public:
    virtual ~Animal() {}
    virtual int32_t sound() const { return 0; }
};

class Dog : public Animal {
public:
    int32_t sound() const override { return 1; }
    virtual int32_t fetch() const { return 10; }
};

class Cat : public Animal {
public:
    int32_t sound() const override { return 2; }
};

class Puppy : public Dog {
public:
    int32_t sound() const override { return 3; }
    int32_t fetch() const override { return 11; }
};

}  // namespace

extern "C" int32_t cpp_dynamic_cast_succeeds(int32_t which) {
    Puppy puppy;
    Cat cat;
    Animal *animal = (which & 1) ? static_cast<Animal *>(&puppy)
                                 : static_cast<Animal *>(&cat);
    /* Succeeds only for the Dog lineage; null otherwise. */
    Dog *dog = dynamic_cast<Dog *>(animal);
    return (dog != 0) ? dog->fetch() : -1;
}

extern "C" int32_t cpp_dynamic_cast_fails(int32_t which) {
    Dog dog;
    Cat cat;
    Animal *animal = (which & 1) ? static_cast<Animal *>(&dog)
                                 : static_cast<Animal *>(&cat);
    Puppy *puppy = dynamic_cast<Puppy *>(animal);
    return (puppy != 0) ? 1 : 0;
}

extern "C" int32_t cpp_typeid_compare(int32_t which) {
    Dog dog;
    Puppy puppy;
    Cat cat;
    const Animal *left;
    const Animal *right;
    switch (which & 3) {
    case 0: left = &dog; right = &dog; break;
    case 1: left = &dog; right = &puppy; break;
    case 2: left = &puppy; right = &puppy; break;
    default: left = &dog; right = &cat; break;
    }
    return (typeid(*left) == typeid(*right)) ? 1 : 0;
}
