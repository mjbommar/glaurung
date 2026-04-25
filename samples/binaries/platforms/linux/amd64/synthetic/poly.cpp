#include <cstdio>
class Animal {
public:
    virtual ~Animal() = default;
    virtual const char* speak() const = 0;
    virtual int legs() const = 0;
};
class Dog : public Animal {
public:
    const char* speak() const override { return "woof"; }
    int legs() const override { return 4; }
};
class Spider : public Animal {
public:
    const char* speak() const override { return "..."; }
    int legs() const override { return 8; }
};
int main() {
    Animal* zoo[] = { new Dog(), new Spider() };
    for (auto* a : zoo) std::printf("%s (%d legs)\n", a->speak(), a->legs());
    for (auto* a : zoo) delete a;
    return 0;
}
