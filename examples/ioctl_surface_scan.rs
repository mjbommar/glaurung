//! Validate engine-native IOCTL surface mapping against real .sys drivers.
//! Run: cargo run --release --example ioctl_surface_scan -- <file.sys> [...]

use glaurung::analysis::ioctl_surface::map_ioctl_surface;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: ioctl_surface_scan <file.sys> [...]");
        std::process::exit(2);
    }
    for path in &args {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{path}: {e}");
                continue;
            }
        };
        let s = map_ioctl_surface(&data, 2, false);
        let total_codes: usize = s.dispatchers.iter().map(|d| d.cmp_codes.len()).sum();
        let total_jt: usize = s.dispatchers.iter().map(|d| d.jump_table.len()).sum();
        println!(
            "== {path} ==\n   {} code-functions; {} dispatcher(s); {} with jump table; \
             {} cmp-codes; {} jt-codes total",
            s.n_code_functions,
            s.dispatchers.len(),
            s.n_jumptable,
            total_codes,
            total_jt,
        );
        for d in &s.dispatchers {
            let resolved = d.jump_table.values().filter(|&&h| h != 0).count();
            println!(
                "  dispatcher @ {:#x}  ({} cmp-codes, {} jt-codes [{} handler-resolved], {} call-handlers)",
                d.va,
                d.cmp_codes.len(),
                d.jump_table.len(),
                resolved,
                d.handlers.len()
            );
        }
        // unique code set across all dispatchers (cmp + jump-table) for parity diffing
        let mut codes: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for d in &s.dispatchers {
            for c in &d.cmp_codes {
                codes.insert(c.code);
            }
            for k in d.jump_table.keys() {
                codes.insert(*k);
            }
        }
        let list: Vec<String> = codes.iter().map(|c| format!("{:#x}", c)).collect();
        println!("CODES {}", list.join(" "));
    }
}
