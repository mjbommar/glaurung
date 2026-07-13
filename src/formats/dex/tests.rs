//! DEX parser tests against a real `d8`-produced fixture.
//!
//! `tests/fixtures/android/sample.dex` is compiled from
//! `tests/fixtures/android/dexsrc/*.java` by `build_dex.sh` (javac + D8).

use super::*;

fn load_sample() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android/sample.dex");
    std::fs::read(path).ok()
}

#[test]
fn detects_and_parses_header() {
    let Some(data) = load_sample() else {
        eprintln!("skip: sample.dex absent (run build_dex.sh)");
        return;
    };
    assert!(DexParser::is_dex(&data));
    let dex = DexParser::parse(&data).expect("parse dex");
    assert_eq!(&dex.header().version, b"035");
    assert_eq!(dex.header().endian_tag, ENDIAN_CONSTANT);
    assert_eq!(dex.header().header_size as usize, HEADER_SIZE);
    assert!(dex.string_count() > 0);
    assert!(dex.class_def_count() >= 2);
}

#[test]
fn string_pool_contains_source_literals() {
    let Some(data) = load_sample() else { return };
    let dex = DexParser::parse(&data).unwrap();
    let strings: Vec<String> = dex.strings().map(|(_, s)| s).collect();
    for expected in ["GlaurungSample", "greet", "secureCall", "render", "isExported"] {
        assert!(
            strings.iter().any(|s| s == expected),
            "string pool missing {expected:?}"
        );
    }
}

#[test]
fn class_names_and_interface_flag() {
    let Some(data) = load_sample() else { return };
    let dex = DexParser::parse(&data).unwrap();
    let names = dex.class_names();
    assert!(names.iter().any(|n| n == "Lcom/glaurung/sample/Sample;"));
    assert!(names.iter().any(|n| n == "Lcom/glaurung/sample/Widget;"));

    // Widget is declared `interface` -> ACC_INTERFACE must be set on its def.
    let widget = dex
        .class_defs()
        .find(|d| dex.class_name(d).as_deref() == Ok("Lcom/glaurung/sample/Widget;"))
        .expect("Widget class_def");
    assert!(widget.access_flags & ACC_INTERFACE != 0, "Widget is an interface");

    let sample = dex
        .class_defs()
        .find(|d| dex.class_name(d).as_deref() == Ok("Lcom/glaurung/sample/Sample;"))
        .expect("Sample class_def");
    assert!(sample.access_flags & ACC_PUBLIC != 0);
    assert!(sample.access_flags & ACC_INTERFACE == 0);
}

#[test]
fn method_signatures_render_with_types() {
    let Some(data) = load_sample() else { return };
    let dex = DexParser::parse(&data).unwrap();
    let sigs: Vec<String> = (0..dex.method_count())
        .filter_map(|i| dex.method_signature(i).ok())
        .collect();

    // greet(String) -> String, add(int,int) -> int, native secureCall(byte[],int) -> long.
    assert!(
        sigs.iter().any(|s| s
            == "Lcom/glaurung/sample/Sample;->greet(Ljava/lang/String;)Ljava/lang/String;"),
        "missing greet signature; got {sigs:?}"
    );
    assert!(sigs.iter().any(|s| s == "Lcom/glaurung/sample/Sample;->add(II)I"));
    assert!(sigs
        .iter()
        .any(|s| s == "Lcom/glaurung/sample/Sample;->secureCall([BI)J"));
    assert!(sigs.iter().any(|s| s == "Lcom/glaurung/sample/Widget;->render(I)V"));
    assert!(sigs
        .iter()
        .any(|s| s == "Lcom/glaurung/sample/Widget;->isExported()Z"));
}

#[test]
fn rejects_non_dex() {
    assert!(!DexParser::is_dex(b"\x7fELF\x02\x01\x01\x00"));
    assert!(DexParser::parse(b"not a dex file at all").is_err());
}
