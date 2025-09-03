//! PE import hash (imphash) computation.

use object::read::Object;
// no object kind filtering necessary; compute on any file with imports

pub fn pe_imphash(data: &[u8]) -> Option<String> {
    let obj = object::read::File::parse(data).ok()?;
    let imports = obj.imports().ok()?;
    let mut entries: Vec<String> = Vec::new();
    for imp in imports {
        let lib = String::from_utf8_lossy(imp.library()).to_ascii_lowercase();
        let name = String::from_utf8_lossy(imp.name()).to_ascii_lowercase();
        if !lib.is_empty() && !name.is_empty() {
            entries.push(format!("{}.{}", lib, name));
        }
    }
    if entries.is_empty() {
        return None;
    }
    entries.sort();
    let joined = entries.join(",");
    let digest = md5::compute(joined.as_bytes());
    Some(format!("{:032x}", digest))
}
