/* The shape that loses functions today: a BASEPRI critical section. */
volatile unsigned int shared_counter;

static inline unsigned int enter_critical(void) {
  unsigned int old;
  __asm__ volatile("mrs %0, basepri" : "=r"(old));
  __asm__ volatile("msr basepri, %0" : : "r"(0x20u));
  return old;
}
static inline void exit_critical(unsigned int old) {
  __asm__ volatile("msr basepri, %0" : : "r"(old));
}

unsigned int guarded_increment(unsigned int by) {
  unsigned int saved = enter_critical();
  shared_counter += by;
  unsigned int now = shared_counter;
  exit_critical(saved);
  return now;
}

unsigned int current_irq(void) {
  unsigned int ipsr;
  __asm__ volatile("mrs %0, ipsr" : "=r"(ipsr));
  return ipsr & 0x1ffu;
}
