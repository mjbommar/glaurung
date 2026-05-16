package corpus.modern;

public record Entry(String name, Mode mode) {
    public String label() {
        return name + ":" + mode.name();
    }
}
