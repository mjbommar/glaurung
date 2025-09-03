use object::read::Object;
use object::ObjectSymbol;

#[test]
fn demangle_cpp_symbols_from_linux_binary_if_present() {
    let path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2";
    if let Ok(data) = std::fs::read(path) {
        let file = match object::read::File::parse(&*data) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut any_demangled = false;
        for sym in file.symbols() {
            if let Ok(name) = sym.name() {
                if name.starts_with("_Z") {
                    if let Some(r) = glaurung::demangle::demangle_one(name) {
                        assert_eq!(r.flavor, glaurung::demangle::SymbolFlavor::Itanium);
                        assert_ne!(r.demangled, r.original);
                        any_demangled = true;
                        break;
                    }
                }
            }
        }
        assert!(any_demangled, "No Itanium-mangled symbol found to demangle");
    } else {
        eprintln!(
            "Skipping C++ demangle integration; sample not present: {}",
            path
        );
    }
}

#[test]
fn demangle_rust_symbols_from_linux_binary_if_present() {
    let path = "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release";
    if let Ok(data) = std::fs::read(path) {
        let file = match object::read::File::parse(&*data) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut any_demangled = false;
        for sym in file.symbols() {
            if let Ok(name) = sym.name() {
                if let Ok(dm) = rustc_demangle::try_demangle(name) {
                    let out = dm.to_string();
                    let res = glaurung::demangle::demangle_one(name)
                        .expect("rust symbol should demangle");
                    assert_eq!(res.flavor, glaurung::demangle::SymbolFlavor::Rust);
                    assert_eq!(res.demangled, out);
                    any_demangled = true;
                    break;
                }
            }
        }
        assert!(any_demangled, "No Rust symbol found to demangle");
    } else {
        eprintln!(
            "Skipping Rust demangle integration; sample not present: {}",
            path
        );
    }
}
