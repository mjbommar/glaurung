package com.glaurung.sample;

public class Sample {
    public static final String TAG = "GlaurungSample";
    private int counter;

    public Sample(int start) { this.counter = start; }

    public int add(int a, int b) { return a + b; }

    public String greet(String name) {
        return "Hello, " + name + "!";
    }

    public native long secureCall(byte[] parcel, int code);

    public static void main(String[] args) {
        Sample s = new Sample(42);
        System.out.println(s.greet(TAG) + " " + s.add(1, 2));
    }
}
