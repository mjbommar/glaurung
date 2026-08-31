// src/core.cpp
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

/**
 * @brief Program entry point: greets, sums argument lengths, and prints results.
 *
 * Constructs a HelloWorld greeter (initially with the message "Hello, C++!"),
 * copies every command-line argument into a std::vector<std::string>, and
 * computes the total combined length (in bytes) of all argument strings.
 *
 * The greeter is then reassigned with the message "Sum printer" and its
 * printMessage() method is invoked. Finally, the total argument length and
 * a placeholder counter value (currently hard-coded to 0, as the original
 * counter source could not be recovered) are written to std::cout.
 *
 * @param argc Number of command-line arguments. Used both as the loop bound
 *             and as the initial reservation size for the argument vector.
 * @param argv Array of NUL-terminated C strings of length @p argc. Each
 *             element is copied into the internal std::vector<std::string>;
 *             none of them may be NULL (otherwise std::string construction
 *             will throw "basic_string::_M_construct null not valid").
 *
 * @return Always returns 0 on normal completion.
 * @retval 0 Successful execution.
 *
 * @note May throw std::length_error ("cannot create std::vector larger than
 *       max_size()") if @p argc is negative or otherwise exceeds the
 *       vector's max_size when passed to reserve().
 * @note The "Counter value:" line currently always prints 0; the true
 *       counter variable was lost during recovery.
 *
 * @code
 * // Invoked by the C runtime, e.g.:
 * //   $ ./prog one two three
 * // Output:
 * //   Hello from HelloWorld: Sum printer
 * //   Total argument length: 17
 * //   Counter value: 0
 * @endcode
 */
#include <iostream>
#include <string>
#include <vector>

class HelloWorld {
public:
    HelloWorld(const std::string &msg);
    void printMessage() const;
};

int main(int argc, char **argv)
{
    // Build the greeter with a fixed message.
    HelloWorld greeter(std::string("Hello, C++!"));

    // Copy every command-line argument into a vector of strings.
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    // Sum the lengths of all arguments.
    std::size_t total_length = 0;
    for (const std::string &a : args) {
        total_length += a.size();
    }

    // Re-construct the greeter with a different message and print it.
    greeter = HelloWorld(std::string("Sum printer"));
    greeter.printMessage();

    std::cout << "Total argument length: " << total_length << std::endl;
    std::cout << "Counter value: " << 0 /* stack_21: counter source not recovered */ << std::endl;

    return 0;
}

