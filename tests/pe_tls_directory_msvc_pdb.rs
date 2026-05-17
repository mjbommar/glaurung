//! Integration test for the TLS callback walker (#199 sub-item)
//! against the #197 MSVC PDB fixtures.
//!
//! Skipped when the fixture dir hasn't been populated yet -- run
//! `tests/fixtures/msvc-pdb/fetch.sh` first.

use std::fs;
use std::path::{Path, PathBuf};

use glaurung::formats::pe::PeParser;

fn fixture(name: &str) -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/msvc-pdb")
        .join(name);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn parse_tls_for(fixture_name: &str) -> Option<glaurung::formats::pe::directories::TlsDirectory> {
    let path = fixture(fixture_name)?;
    let data = fs::read(&path).ok()?;
    let parser = PeParser::new(&data).expect("parse PE");
    Some(parser.tls().expect("walk TLS").clone())
}

#[test]
fn ntoskrnl_tls_walked_when_present() {
    let Some(td) = parse_tls_for("ntoskrnl.exe") else {
        eprintln!("skip: tests/fixtures/msvc-pdb/ntoskrnl.exe absent (run fetch.sh)");
        return;
    };
    // ntoskrnl is a kernel binary; it may or may not expose a TLS
    // callback array depending on the build. Either way the parser
    // must return cleanly (no panic; either empty or non-empty).
    assert!(
        td.callback_count() <= 1024,
        "callback count overflowed cap: {}",
        td.callback_count()
    );
    assert!(
        td.stop_reasons
            .iter()
            .all(|r| !r.contains("panic") && !r.contains("FATAL")),
        "soft errors only: {:?}",
        td.stop_reasons
    );
    // RVAs (if any) match callback VAs minus ImageBase invariant.
    for rva in &td.callback_rvas {
        assert!(*rva > 0, "RVAs should be non-zero");
    }
    eprintln!(
        "ntoskrnl.exe: tls_header={} callbacks={} stop_reasons={:?}",
        td.has_tls_header(),
        td.callback_count(),
        td.stop_reasons
    );
}

#[test]
fn driver_fixtures_tls_walk_cleanly() {
    // Drivers commonly have TLS callbacks for security-cookie init.
    // We don't assert presence (varies by build) -- we assert the
    // walker returns cleanly across every driver fixture.
    for name in &["tcpip.sys", "dxgkrnl.sys", "win32k.sys"] {
        let Some(td) = parse_tls_for(name) else {
            eprintln!("skip: tests/fixtures/msvc-pdb/{} absent", name);
            continue;
        };
        assert!(td.callback_count() <= 1024, "{}: cap overflow", name);
        // address_of_callbacks invariant: if non-zero, callbacks were
        // either walked or rooted in a stop_reason.
        if td.address_of_callbacks != 0 {
            assert!(
                td.has_callbacks() || !td.stop_reasons.is_empty(),
                "{}: callbacks VA set but no walk + no stop_reason",
                name
            );
        }
        eprintln!(
            "{}: tls_header={} callbacks={} stop_reasons={:?}",
            name,
            td.has_tls_header(),
            td.callback_count(),
            td.stop_reasons
        );
    }
}

#[test]
fn userland_fixtures_tls_walk_cleanly() {
    // Userland fixtures: ntdll/kernel32/lsass/spoolsv. Same shape:
    // walker must not panic, callback count bounded, RVAs sane.
    for name in &["ntdll.dll", "kernel32.dll", "lsass.exe", "spoolsv.exe"] {
        let Some(td) = parse_tls_for(name) else {
            eprintln!("skip: tests/fixtures/msvc-pdb/{} absent", name);
            continue;
        };
        assert!(td.callback_count() <= 1024, "{}: cap overflow", name);
        eprintln!(
            "{}: tls_header={} callbacks={} stop_reasons={:?}",
            name,
            td.has_tls_header(),
            td.callback_count(),
            td.stop_reasons
        );
    }
}

#[test]
fn tls_parser_idempotent() {
    // Calling .tls() twice must return the same cached directory
    // (lazy OnceCell). Use any fixture; skip cleanly if absent.
    let Some(path) = fixture("ntdll.dll") else {
        eprintln!("skip: tests/fixtures/msvc-pdb/ntdll.dll absent");
        return;
    };
    let data = fs::read(&path).expect("read");
    let parser = PeParser::new(&data).expect("parse");
    let a = parser.tls().expect("walk 1").clone();
    let b = parser.tls().expect("walk 2").clone();
    assert_eq!(a.callback_count(), b.callback_count());
    assert_eq!(a.address_of_callbacks, b.address_of_callbacks);
    assert_eq!(a.callbacks, b.callbacks);
}
