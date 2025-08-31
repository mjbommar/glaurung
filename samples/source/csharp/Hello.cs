using System;

public class Hello
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello from C# (Mono)!" + (args.Length > 0 ? " " + string.Join(",", args) : ""));
    }
}

