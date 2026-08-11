volatile int terminal_loop_state;

__attribute__((noinline)) void terminal_setup(void) {
    terminal_loop_state += 1;
}

__attribute__((noinline)) int terminal_get_state(void) {
    return terminal_loop_state;
}

__attribute__((noinline)) void terminal_start(void) {
    terminal_loop_state += 2;
}

int main(void) {
    terminal_setup();
    if (terminal_get_state() == 1) {
        terminal_start();
    }
    for (;;) {
    }
}
