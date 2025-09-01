use crate::core::triage::PackerMatch;

pub fn detect_packers(data: &[u8]) -> Vec<PackerMatch> {
    let mut out = Vec::new();
    let hay = data;

    // UPX
    let mut upx = 0.0f32;
    if memchr::memmem::find(hay, b"UPX!").is_some() {
        upx += 0.4;
    }
    if memchr::memmem::find(hay, b"UPX0").is_some() {
        upx += 0.3;
    }
    if memchr::memmem::find(hay, b"UPX1").is_some() {
        upx += 0.3;
    }
    // Version/signature hints increase confidence
    if memchr::memmem::find(hay, b"$Id: UPX ").is_some()
        || memchr::memmem::find(hay, b"UPX ").is_some()
    {
        upx += 0.2;
    }
    if upx > 0.0 {
        out.push(PackerMatch::new("UPX".to_string(), upx.min(1.0)));
    }

    // ASPack
    if memchr::memmem::find(hay, b"ASPack").is_some() {
        out.push(PackerMatch::new("ASPack".into(), 0.9));
    }

    // PECompact
    if memchr::memmem::find(hay, b"PECompact").is_some()
        || memchr::memmem::find(hay, b"PEC2").is_some()
    {
        out.push(PackerMatch::new("PECompact".into(), 0.85));
    }

    // Petite
    if memchr::memmem::find(hay, b"Petite").is_some() {
        out.push(PackerMatch::new("Petite".into(), 0.8));
    }

    // FSG
    if memchr::memmem::find(hay, b"FSG!").is_some() {
        out.push(PackerMatch::new("FSG".into(), 0.85));
    }

    // MPRESS
    if memchr::memmem::find(hay, b"MPRESS").is_some() {
        out.push(PackerMatch::new("MPRESS".into(), 0.85));
    }

    // Themida/WinLicense
    if memchr::memmem::find(hay, b"Themida").is_some()
        || memchr::memmem::find(hay, b"WinLicense").is_some()
    {
        out.push(PackerMatch::new("Themida/WinLicense".into(), 0.9));
    }

    // VMProtect (section names often .vmp0/.vmp1 in PE, but scan raw too)
    if memchr::memmem::find(hay, b".vmp0").is_some()
        || memchr::memmem::find(hay, b".vmp1").is_some()
    {
        out.push(PackerMatch::new("VMProtect".into(), 0.75));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_upx_on_real_samples() {
        let candidates = [
            "samples/packed/hello-rust-release.upx9",
            "samples/packed/hello-rust-debug.upx9",
            "samples/packed/hello-go.upx9",
        ];
        for p in candidates {
            if let Ok(d) = fs::read(p) {
                let v = detect_packers(&d);
                assert!(v.iter().any(|m| m.name == "UPX"));
            }
        }
    }
}
