//! Linux `.ko` ioctl-dispatch tests against a real AArch64 driver object.
//!
//! `tests/fixtures/android/foo_drv.ko` is compiled by
//! `aarch64-linux-gnu-gcc -O2 -c` from `drv.c` (a `file_operations`-shaped TU
//! with an `unlocked_ioctl` handler switching on `_IOC`-encoded commands). Kernel
//! modules are `ET_REL` objects, so a `-c` relocatable ELF is structurally
//! faithful: the fops slots carry `R_AARCH64_ABS64` relocations to the handlers.

use super::*;

fn load_ko() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android/foo_drv.ko");
    std::fs::read(path).ok()
}

// The four commands drv.c declares, via _IOC(dir, 0xB7, nr, size).
const FOO_GET: u32 = 0x8004_b701; // read,  size 4, nr 1
const FOO_SET: u32 = 0x4004_b702; // write, size 4, nr 2
const FOO_RST: u32 = 0x0000_b703; // none,  size 0, nr 3
const FOO_XCHG: u32 = 0xc008_b704; // readwrite, size 8, nr 4

#[test]
fn ioc_decoder_matches_encoding() {
    let g = decode_ioc(FOO_GET);
    assert_eq!(g.dir, IocDir::Read);
    assert_eq!(g.type_, 0xB7);
    assert_eq!(g.nr, 1);
    assert_eq!(g.size, 4);

    assert_eq!(decode_ioc(FOO_SET).dir, IocDir::Write);
    assert_eq!(decode_ioc(FOO_RST).dir, IocDir::None);
    assert_eq!(decode_ioc(FOO_RST).size, 0);
    let x = decode_ioc(FOO_XCHG);
    assert_eq!(x.dir, IocDir::ReadWrite);
    assert_eq!(x.size, 8);
    assert_eq!(x.nr, 4);
}

#[test]
fn resolves_fops_ioctl_slots() {
    let Some(data) = load_ko() else {
        eprintln!("skip: foo_drv.ko fixture absent");
        return;
    };
    let surface = map_linux_ioctl_surface(&data);

    // Both the unlocked and compat slots of foo_fops must be recovered.
    let unlocked = surface
        .handlers
        .iter()
        .find(|h| !h.is_compat)
        .expect("unlocked_ioctl handler resolved");
    assert_eq!(unlocked.fops_symbol, "foo_fops");
    assert_eq!(unlocked.handler_symbol, "foo_ioctl");
    // unlocked_ioctl is field index 9 -> byte offset 0x48 in the fixture struct.
    assert_eq!(unlocked.slot_offset, 0x48);

    let compat = surface
        .handlers
        .iter()
        .find(|h| h.is_compat)
        .expect("compat_ioctl handler resolved");
    assert_eq!(compat.handler_symbol, "foo_compat_ioctl");
    assert_eq!(compat.slot_offset, 0x50);
}

#[test]
fn enumerates_command_surface_from_handler() {
    let Some(data) = load_ko() else { return };
    let surface = map_linux_ioctl_surface(&data);

    let unlocked = surface
        .handlers
        .iter()
        .find(|h| h.handler_symbol == "foo_ioctl")
        .expect("foo_ioctl");

    let raws: std::collections::BTreeSet<u32> =
        unlocked.commands.iter().map(|c| c.raw).collect();
    let expected: std::collections::BTreeSet<u32> =
        [FOO_GET, FOO_SET, FOO_RST, FOO_XCHG].into_iter().collect();
    assert_eq!(raws, expected, "recovered ioctl command surface");

    // Every recovered command carries the driver's 0xB7 magic type.
    assert!(unlocked.commands.iter().all(|c| c.type_ == 0xB7));
}

#[test]
fn scanner_handles_immediate_and_wide_constants() {
    // mov w1,#... is the cmd reg; craft: cmp w1,#0x10 form via small imm is
    // covered by the real handler. Here assert the wide-constant path directly.
    // Encodings: movz w0,#0xb701 ; movk w0,#0x8004,lsl#16 ; cmp w1,w0.
    let code: Vec<u8> = [0x5296e020u32, 0x72b00080, 0x6b00003f]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let cmds = scan_aarch64_ioctl_cmds(&code);
    assert_eq!(cmds, vec![FOO_GET]);
}

#[test]
fn non_elf_input_is_empty_not_error() {
    let surface = map_linux_ioctl_surface(b"not an elf");
    assert!(surface.handlers.is_empty());
}
