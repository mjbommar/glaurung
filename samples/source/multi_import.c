extern int puts(const char *);
extern int printf(const char *, ...);
extern void *malloc(unsigned long);
extern void free(void *);
extern int strlen(const char *);

int main(int argc, char **argv) {
    char *buf = malloc(64);
    if (!buf) return 1;
    printf("arg0 len=%d\n", strlen(argv[0]));
    puts("done");
    free(buf);
    return 0;
}
