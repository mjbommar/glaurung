/* A .ko-shaped translation unit: file_operations with an unlocked_ioctl
   handler that switches on _IOC-encoded command codes. No kernel headers;
   the struct mirrors the real fn-pointer layout so the fops -> handler
   relocation wiring matches a real module (which is also ET_REL). */
typedef unsigned int u32;
typedef unsigned long ulong;
struct file; struct inode;

/* _IOC(dir,type,nr,size): dir<<30 | size<<16 | type<<8 | nr */
#define _IOC(dir,type,nr,size) (((dir)<<30)|((size)<<16)|((type)<<8)|(nr))
#define FOO_MAGIC 0xB7
#define FOO_GET   _IOC(2,FOO_MAGIC,1,4)   /* read  */
#define FOO_SET   _IOC(1,FOO_MAGIC,2,4)   /* write */
#define FOO_RST   _IOC(0,FOO_MAGIC,3,0)   /* none  */
#define FOO_XCHG  _IOC(3,FOO_MAGIC,4,8)   /* rw    */

static long foo_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    long r = 0;
    switch (cmd) {
        case FOO_GET:  r = (long)arg + 1; break;
        case FOO_SET:  r = (long)arg - 1; break;
        case FOO_RST:  r = 0; break;
        case FOO_XCHG: r = (long)arg ^ 0x5a; break;
        default: r = -22; /* -EINVAL */
    }
    return r;
}
static long foo_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    return foo_ioctl(f, cmd, arg);
}
static int foo_open(struct inode *i, struct file *f) { return 0; }
static int foo_release(struct inode *i, struct file *f) { return 0; }

/* Layout mirrors the head of struct file_operations (owner, llseek, read,
   write, ... then unlocked_ioctl, compat_ioctl, open, ... release). */
struct file_operations {
    void *owner, *llseek, *read, *write, *read_iter, *write_iter, *iopoll,
         *iterate_shared, *poll;
    long (*unlocked_ioctl)(struct file*, unsigned int, unsigned long);
    long (*compat_ioctl)(struct file*, unsigned int, unsigned long);
    void *mmap;
    int  (*open)(struct inode*, struct file*);
    void *flush;
    int  (*release)(struct inode*, struct file*);
};
const struct file_operations foo_fops = {
    .unlocked_ioctl = foo_ioctl,
    .compat_ioctl   = foo_compat_ioctl,
    .open           = foo_open,
    .release        = foo_release,
};
