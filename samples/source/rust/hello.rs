// Rust sample with various language features for binary analysis

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Global constant
const GLOBAL_CONSTANT: i32 = 42;

// Static mutable (unsafe)
static mut GLOBAL_COUNTER: i32 = 0;

// Trait definition
trait Speaker {
    fn speak(&self) -> String;
}

// Struct with generics
#[derive(Debug, Clone)]
struct Application<T> {
    name: String,
    version: String,
    data: T,
}

// Trait implementation
impl<T: std::fmt::Debug> Speaker for Application<T> {
    fn speak(&self) -> String {
        format!("{} v{} with data: {:?}", self.name, self.version, self.data)
    }
}

// Enum with pattern matching
#[derive(Debug)]
enum Operation {
    Add(i32, i32),
    Multiply(i32, i32),
    Divide(i32, i32),
    Print(String),
}

// Function with Result type
fn risky_operation(value: i32) -> Result<i32, String> {
    if value == 0 {
        Err("Cannot process zero".to_string())
    } else if value < 0 {
        Err("Negative values not supported".to_string())
    } else {
        Ok(value * 2)
    }
}

// Async-like function with threads
fn parallel_computation(values: Vec<i32>) -> Vec<i32> {
    let shared_results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];
    
    for value in values {
        let results = Arc::clone(&shared_results);
        let handle = thread::spawn(move || {
            // Simulate work
            thread::sleep(Duration::from_millis(10));
            let computed = value * value;
            let mut res = results.lock().unwrap();
            res.push(computed);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let results = shared_results.lock().unwrap();
    results.clone()
}

// Macro definition
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!("[DEBUG] {}", format!($($arg)*));
    };
}

// Function with iterator chains
fn process_data(data: &[i32]) -> i32 {
    data.iter()
        .filter(|&&x| x > 0)
        .map(|&x| x * 2)
        .fold(0, |acc, x| acc + x)
}

// Closure example
fn create_multiplier(factor: i32) -> impl Fn(i32) -> i32 {
    move |x| x * factor
}

fn main() {
    println!("Hello, World from Rust!");
    
    // Command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        println!("Arguments: {:?}", &args[1..]);
    }
    
    // Struct usage with generics
    let app = Application {
        name: String::from("glaurung"),
        version: String::from("1.0.0"),
        data: HashMap::from([
            ("feature1", true),
            ("feature2", false),
            ("feature3", true),
        ]),
    };
    println!("Application: {}", app.speak());
    
    // Pattern matching
    let operations = vec![
        Operation::Add(10, 20),
        Operation::Multiply(5, 7),
        Operation::Divide(100, 5),
        Operation::Print(String::from("Processing complete")),
    ];
    
    for op in operations {
        match op {
            Operation::Add(a, b) => println!("Add: {} + {} = {}", a, b, a + b),
            Operation::Multiply(a, b) => println!("Multiply: {} × {} = {}", a, b, a * b),
            Operation::Divide(a, b) => {
                if b != 0 {
                    println!("Divide: {} ÷ {} = {}", a, b, a / b);
                } else {
                    println!("Division by zero!");
                }
            }
            Operation::Print(msg) => println!("Message: {}", msg),
        }
    }
    
    // Error handling with Result
    let test_values = vec![10, 0, -5, 42];
    for val in test_values {
        match risky_operation(val) {
            Ok(result) => println!("Operation({}) = {}", val, result),
            Err(e) => println!("Error for {}: {}", val, e),
        }
    }
    
    // Thread-based parallel computation
    let numbers = vec![1, 2, 3, 4, 5];
    let results = parallel_computation(numbers.clone());
    println!("Parallel computation results: {:?}", results);
    
    // Iterator chains
    let data = vec![1, -2, 3, -4, 5, 6];
    let sum = process_data(&data);
    println!("Processed sum: {}", sum);
    
    // Closure usage
    let multiply_by_3 = create_multiplier(3);
    println!("3 × 7 = {}", multiply_by_3(7));
    
    // Unsafe block
    unsafe {
        GLOBAL_COUNTER += 1;
        println!("Global counter: {}", GLOBAL_COUNTER);
    }
    
    // Macro usage
    debug_print!("Program completed successfully");
    
    // String manipulation
    let mut text = String::from("Rust");
    text.push_str(" is memory safe!");
    println!("{}", text);
    
    // Option type
    let maybe_number: Option<i32> = Some(42);
    if let Some(n) = maybe_number {
        println!("The answer is {}", n);
    }
    
    std::process::exit(0);
}

// Module with tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_risky_operation() {
        assert!(risky_operation(10).is_ok());
        assert!(risky_operation(0).is_err());
        assert!(risky_operation(-5).is_err());
    }
    
    #[test]
    fn test_process_data() {
        let data = vec![1, -2, 3, -4, 5];
        assert_eq!(process_data(&data), 18); // (1+3+5)*2
    }
}