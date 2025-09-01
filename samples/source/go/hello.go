package main

import (
    "fmt"
    "os"
    "runtime"
    "sync"
    "time"
)

// Global variables
var (
    globalCounter int = 42
    globalMutex   sync.Mutex
)

// Interface example
type Speaker interface {
    Speak() string
}

// Struct with methods
type Application struct {
    Name    string
    Version string
    Debug   bool
}

func (a *Application) Speak() string {
    return fmt.Sprintf("%s v%s", a.Name, a.Version)
}

func (a *Application) String() string {
    return a.Speak()
}

// Goroutine function
func worker(id int, jobs <-chan int, results chan<- int, wg *sync.WaitGroup) {
    defer wg.Done()
    for job := range jobs {
        time.Sleep(10 * time.Millisecond)
        results <- job * 2
    }
}

// Function with defer and panic recovery
func riskyOperation() (result int, err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("recovered from panic: %v", r)
        }
    }()
    
    // Simulate some work
    result = 100
    
    // Intentional panic for testing
    if false {
        panic("simulated panic")
    }
    
    return result, nil
}

// Generic function (Go 1.18+)
func mapSlice[T any, U any](slice []T, fn func(T) U) []U {
    result := make([]U, len(slice))
    for i, v := range slice {
        result[i] = fn(v)
    }
    return result
}

func main() {
    fmt.Println("Hello, World from Go!")
    fmt.Printf("Runtime: %s/%s\n", runtime.GOOS, runtime.GOARCH)
    fmt.Printf("Go version: %s\n", runtime.Version())
    
    // Struct usage
    app := &Application{
        Name:    "glaurung",
        Version: "1.0.0",
        Debug:   true,
    }
    fmt.Printf("Application: %s\n", app)
    
    // Channel and goroutine example
    numJobs := 5
    jobs := make(chan int, numJobs)
    results := make(chan int, numJobs)
    
    var wg sync.WaitGroup
    wg.Add(3)
    
    // Start workers
    for w := 1; w <= 3; w++ {
        go worker(w, jobs, results, &wg)
    }
    
    // Send jobs
    for j := 1; j <= numJobs; j++ {
        jobs <- j
    }
    close(jobs)
    
    // Wait for completion in background
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // Collect results
    fmt.Print("Results: ")
    for result := range results {
        fmt.Printf("%d ", result)
    }
    fmt.Println()
    
    // Map/slice operations with generics
    numbers := []int{1, 2, 3, 4, 5}
    doubled := mapSlice(numbers, func(n int) int { return n * 2 })
    fmt.Printf("Doubled: %v\n", doubled)
    
    // Error handling
    if value, err := riskyOperation(); err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Printf("Operation result: %d\n", value)
    }
    
    // Command line arguments
    if len(os.Args) > 1 {
        fmt.Printf("Arguments: %v\n", os.Args[1:])
    }
    
    os.Exit(0)
}