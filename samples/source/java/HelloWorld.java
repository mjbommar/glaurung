// Simple hello world program in Java with some complexity for analysis
public class HelloWorld {
    // Global constant
    private static final int GLOBAL_COUNTER = 42;

    // Instance variables
    private String message;
    private int counter;

    // Constructor
    public HelloWorld(String message) {
        this.message = message;
        this.counter = 0;
    }

    // Default constructor
    public HelloWorld() {
        this("Hello, World from Java!");
    }

    // Method to print message
    public void printMessage() {
        System.out.println(message);
        counter++;
    }

    // Getter for counter
    public int getCounter() {
        return counter;
    }

    // Static method
    public static void printGlobalInfo() {
        System.out.println("Global counter: " + GLOBAL_COUNTER);
    }

    // Main method
    public static void main(String[] args) {
        HelloWorld hw = new HelloWorld();
        hw.printMessage();

        // Calculate sum of argument lengths
        int sum = 0;
        for (String arg : args) {
            sum += arg.length();
        }

        System.out.println("Number of arguments: " + args.length);
        System.out.println("Total argument length: " + sum);
        System.out.println("Counter value: " + hw.getCounter());

        // Call static method
        HelloWorld.printGlobalInfo();

        // Create another instance
        HelloWorld hw2 = new HelloWorld("Second instance");
        hw2.printMessage();
    }
}