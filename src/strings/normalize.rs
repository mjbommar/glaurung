//! Lightweight normalization helpers for defanged IOCs.

use std::borrow::Cow;

/// Normalize common defanging schemes in a conservative way.
/// - hxxp:// -> http:// ; hxxps:// -> https://
/// - [.] and (.) -> .
///   The input may be large; if it's longer than `max_len`, we return it as-is
///   to avoid quadratic work.
pub fn normalize_defanged<'a>(s: &'a str, max_len: usize) -> Cow<'a, str> {
    if s.len() > max_len {
        return Cow::Borrowed(s);
    }

    // Quick prechecks to avoid allocations when not needed.
    let needs = s.contains("hxxp") || s.contains("[.]") || s.contains("(.)");
    if !needs {
        return Cow::Borrowed(s);
    }

    let mut out = s.replace("hxxps://", "https://");
    out = out.replace("hxxp://", "http://");
    out = out.replace("[.]", ".");
    out = out.replace("(.)", ".");
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_basic_defangs() {
        let s = "visit hxxps://ex[.]ample(.)com";
        let n = normalize_defanged(s, 4096);
        assert_eq!(n, "visit https://ex.ample.com");
    }
}
