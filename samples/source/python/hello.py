#!/usr/bin/env python3
"""
Simple hello world program in Python with some complexity for analysis
"""

import sys
import os

# Global constant
GLOBAL_COUNTER = 42

class HelloWorld:
    """A simple hello world class"""

    def __init__(self, message="Hello, World from Python!"):
        self.message = message
        self.counter = 0

    def print_message(self):
        """Print the message and increment counter"""
        print(self.message)
        self.counter += 1

    def get_counter(self):
        """Get the current counter value"""
        return self.counter

def calculate_arg_sum(args):
    """Calculate sum of argument lengths"""
    return sum(len(arg) for arg in args)

def main():
    """Main function"""
    hw = HelloWorld()
    hw.print_message()

    # Calculate sum of argument lengths
    args = sys.argv[1:]  # Skip script name
    total_length = calculate_arg_sum(args)

    print(f"Number of arguments: {len(args)}")
    print(f"Total argument length: {total_length}")
    print(f"Counter value: {hw.get_counter()}")
    print(f"Global counter: {GLOBAL_COUNTER}")

    # Print some system info
    print(f"Python version: {sys.version}")
    print(f"Script path: {os.path.abspath(__file__)}")

    # Create another instance
    hw2 = HelloWorld("Second instance from Python")
    hw2.print_message()

if __name__ == "__main__":
    main()