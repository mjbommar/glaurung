#include <iostream>
#include <string>
#include <vector>
#include <memory>

// Simple hello world with some complexity for analysis
class HelloWorld {
private:
    std::string message;
    int counter;

public:
    HelloWorld(const std::string& msg = "Hello, World from C++!") : message(msg), counter(0) {}

    void printMessage() {
        std::cout << message << std::endl;
        counter++;
    }

    int getCounter() const { return counter; }
};

int main(int argc, char* argv[]) {
    HelloWorld hw;
    hw.printMessage();

    // Some basic operations to create interesting disassembly
    int sum = 0;
    std::vector<std::string> args(argv, argv + argc);

    for (const auto& arg : args) {
        sum += arg.length();
    }

    // Use smart pointer
    auto printer = std::make_unique<HelloWorld>("Sum printer");
    printer->printMessage();

    std::cout << "Total argument length: " << sum << std::endl;
    std::cout << "Counter value: " << hw.getCounter() << std::endl;

    return 0;
}

// Global variable
int global_counter = 42;

// Static function
static void static_function() {
    static int static_var = 0;
    static_var++;
    std::cout << "Static function called " << static_var << " times" << std::endl;
}