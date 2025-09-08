use crate::core::binary::{Arch, Endianness, Format};
use crate::core::disassembler::Disassembler;
use crate::core::triage::formats::{FormatSpecificTriage, PeTriageInfo};
use crate::core::triage::{
    Budgets, ContainerChild, EntropyAnalysis, PackerMatch, StringsSummary, TriageVerdict,
    TriagedArtifact,
};
use crate::core::triage::{TriageError, TriageErrorKind, TriageHint};
use crate::strings::StringsConfig;
use crate::symbols::{self, BudgetCaps};
#[cfg(feature = "python-ext")]
use crate::triage::config::TriageConfig;
use crate::triage::config::{EntropyConfig, PackerConfig, SimilarityConfig};
use crate::triage::entropy::analyze_entropy;
use crate::triage::format_detection::{derive_format_from_hint, is_container_hint};
use crate::triage::headers;
use crate::triage::heuristics::{architecture, endianness};
use crate::triage::io::{
    IOLimits, SafeFileReader, MAX_ENTROPY_SIZE, MAX_HEADER_SIZE, MAX_SNIFF_SIZE,
};
use crate::triage::packers::detect_packers;
use crate::triage::parsers;
use crate::triage::recurse::RecursionEngine;
use crate::triage::score;
use crate::triage::sniffers::CombinedSniffer;
use chrono::Utc;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info};

fn compute_disasm_preview(
    data: &[u8],
    arch_guesses: &[(Arch, f32)],
    e_guess: Endianness,
    max_instructions: usize,
    max_bytes: usize,
    max_time_ms: u64,
) -> Option<Vec<String>> {
    use crate::core::disassembler::Architecture as DArch;
    let (barch, _conf) = arch_guesses.first().cloned()?;
    let darch: DArch = barch.into();
    let backend = crate::disasm::registry::for_arch(darch, e_guess)?;
    let bits = darch.address_bits();
    let addr = crate::core::address::Address::new(
        crate::core::address::AddressKind::VA,
        0,
        bits,
        None,
        None,
    )
    .ok()?;
    let mut out = Vec::new();
    let mut off = 0usize;
    let limit = data.len().min(max_bytes);
    let t0 = std::time::Instant::now();
    for _ in 0..max_instructions {
        if off >= limit {
            break;
        }
        if t0.elapsed().as_millis() as u64 > max_time_ms {
            break;
        }
        let cur = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            addr.value.saturating_add(off as u64),
            bits,
            None,
            None,
        )
        .ok()?;
        match backend.disassemble_instruction(&cur, &data[off..limit]) {
            Ok(ins) => {
                if ins.length == 0 {
                    break;
                }
                out.push(ins.disassembly());
                off += ins.length as usize;
            }
            Err(_) => break,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn generate_id(path: Option<&Path>, size: usize) -> String {
    let mut hasher = Sha256::new();
    if let Some(p) = path {
        hasher.update(p.to_string_lossy().as_bytes());
    }
    hasher.update(size.to_le_bytes());
    // Use non-deprecated timestamp API; include nanos for uniqueness
    let nanos: i128 = Utc::now().timestamp_nanos_opt().unwrap_or_default().into();
    hasher.update(nanos.to_le_bytes());
    let digest = hasher.finalize();
    format!(
        "triage_{}_{:x}",
        Utc::now().timestamp_millis(),
        u64::from_le_bytes(digest[..8].try_into().unwrap())
    )
}

/// Performs content sniffing to identify file type hints.
fn sniff_content(sniff_buf: &[u8], path: &str) -> (Vec<TriageHint>, Vec<TriageError>) {
    debug!(phase = "sniffing", "content+extension sniff");
    let sn = CombinedSniffer::sniff(sniff_buf, Some(Path::new(path)));
    (sn.hints, sn.errors)
}

/// Validates file headers to identify binary format candidates.
fn validate_headers(header_buf: &[u8]) -> (Vec<TriageVerdict>, Vec<TriageError>) {
    debug!(phase = "headers", "validate");
    let hdr = headers::validate(header_buf);
    (hdr.candidates, hdr.errors)
}

/// Performs heuristic analysis including entropy, endianness, and architecture detection.
fn analyze_heuristics(
    heur_buf: &[u8],
) -> (
    EntropyAnalysis,
    Option<f64>,
    (Endianness, f32),
    Vec<(Arch, f32)>,
) {
    debug!(phase = "entropy", "compute");
    let ecfg = EntropyConfig::default();
    let ea = analyze_entropy(heur_buf, &ecfg);
    let entropy = ea.summary.overall;

    debug!(phase = "heuristics", "endianness and arch");
    let (e_guess, e_conf) = endianness::guess(heur_buf);
    let arch_guesses = architecture::infer(heur_buf);

    (ea, entropy, (e_guess, e_conf), arch_guesses)
}

/// Extracts strings from the heuristics buffer with language detection.
fn extract_strings(
    heur_buf: &[u8],
    strings_cfg: &StringsConfig,
    hints: &[TriageHint],
    entropy: Option<f64>,
) -> Option<StringsSummary> {
    debug!(phase = "strings", "extract with language detection");

    // Adjust strings settings for compressed/high-entropy inputs
    let mut adj = strings_cfg.clone();
    let is_containerish = hints.iter().any(is_container_hint);
    if is_containerish || entropy.unwrap_or(0.0) > 7.2 {
        adj.min_length = adj.min_length.max(8);
    }

    let s = crate::strings::extract_summary(heur_buf, &adj);
    if s.ascii_count == 0 && s.utf16le_count == 0 && s.utf16be_count == 0 {
        None
    } else {
        Some(s)
    }
}

/// Discovers containers and packers within the binary.
fn discover_containers_and_packers(
    heur_buf: &[u8],
    hints: &[TriageHint],
    max_recursion_depth: usize,
) -> (Option<Vec<ContainerChild>>, u32, Option<Vec<PackerMatch>>) {
    debug!(phase = "parsers", "structured parse probes");

    // Container discovery
    let (containers, rec_depth) = {
        // Use recursion engine to discover immediate children (containers)
        let engine = RecursionEngine::new(max_recursion_depth);
        let mut tmp_budget = Budgets::new(0, 0, 0);
        let v = engine.discover_children(heur_buf, &mut tmp_budget, 0);
        let mut vv = v;

        // Deduplicate for JAR: prefer a single zip entry
        let is_jar = hints.iter().any(|h| h.label.as_deref() == Some("jar"));
        if is_jar {
            let mut zips: Vec<_> = vv
                .iter()
                .filter(|c| c.type_name.eq_ignore_ascii_case("zip"))
                .cloned()
                .collect();
            if !zips.is_empty() {
                // keep zip at offset 0 if present, else the largest
                zips.sort_by_key(|c| (c.offset, std::cmp::Reverse(c.size)));
                let keep = if let Some(first) = zips.iter().find(|c| c.offset == 0) {
                    first.clone()
                } else {
                    zips[0].clone()
                };
                vv.retain(|c| !c.type_name.eq_ignore_ascii_case("zip"));
                vv.push(keep);
            }
        }
        (
            if vv.is_empty() { None } else { Some(vv) },
            tmp_budget.recursion_depth,
        )
    };

    // Packer detection is performed in build_artifact_from_buffers where we have access to config
    // Return None here; actual packer results will be computed later with the provided config.
    let packers = None;

    (containers, rec_depth, packers)
}

/// Merges errors from different analysis phases and adds budget-related errors.
fn merge_errors(
    sniff_errors: Vec<TriageError>,
    header_errors: Vec<TriageError>,
    hints: &[TriageHint],
    header_formats: &[Format],
    container_labels: &[String],
    hit_byte_limit: bool,
    limit_bytes: u64,
    initial_bytes_read: u64,
) -> Option<Vec<TriageError>> {
    // Cross-check sniffer hints vs header verdicts
    let mut cross = compute_sniffer_header_mismatches(hints, header_formats, container_labels);

    // Merge non-fatal errors and append budget notice if applicable
    let mut merged_errors_vec: Vec<TriageError> = {
        let mut e = sniff_errors;
        e.extend(header_errors);
        e.append(&mut cross);
        e
    };

    if hit_byte_limit {
        merged_errors_vec.push(TriageError::new(
            TriageErrorKind::BudgetExceeded,
            Some(format!(
                "Byte limit reached (limit_bytes={} bytes_read={})",
                limit_bytes, initial_bytes_read
            )),
        ));
    }

    if merged_errors_vec.is_empty() {
        None
    } else {
        Some(merged_errors_vec)
    }
}

// Compute header vs sniffer mismatch errors.
// - header_formats: formats derived from header validation.
// - container_labels: names from container detection (e.g., zip, tar).
pub(crate) fn compute_sniffer_header_mismatches(
    hints: &[TriageHint],
    header_formats: &[Format],
    container_labels: &[String],
) -> Vec<TriageError> {
    if header_formats.is_empty() || hints.is_empty() {
        return Vec::new();
    }
    // Do not mark mismatch if hint clearly indicates a container that we detected.
    let container_set: std::collections::HashSet<String> = container_labels
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let mut errors = Vec::new();
    for h in hints {
        // Skip container hints when containers detected; that's not a header mismatch.
        if is_container_hint(h) {
            if let Some(label) = &h.label {
                if container_set.contains(&label.to_ascii_lowercase()) {
                    continue;
                }
            }
        }
        if let Some(hfmt) = derive_format_from_hint(h) {
            if !header_formats.contains(&hfmt) {
                errors.push(TriageError::new(
                    TriageErrorKind::SnifferMismatch,
                    Some(format!(
                        "Sniffer suggests {:?} but headers indicate {:?}",
                        hfmt, header_formats
                    )),
                ));
            }
        }
    }
    errors
}

#[allow(clippy::too_many_arguments)]
fn build_artifact_from_buffers(
    path: String,
    size_bytes: usize,
    sniff_buf: &[u8],
    header_buf: &[u8],
    heur_buf: &[u8],
    max_recursion_depth: usize,
    initial_bytes_read: u64,
    limit_bytes: u64,
    declared_max_recursion: usize,
    hit_byte_limit: bool,
    strings_cfg: &StringsConfig,
    packer_cfg: &PackerConfig,
    sim_cfg: &SimilarityConfig,
) -> TriagedArtifact {
    let t0 = Instant::now();
    let id = generate_id(None, size_bytes);
    let span =
        tracing::info_span!("triage", triage_id = %id, path = %path, size_bytes = size_bytes);
    let _g = span.enter();
    info!("start");

    // Phase 1: Content sniffing
    let (hints, sniff_errors) = sniff_content(sniff_buf, &path);

    // Phase 2: Header validation
    let (verdicts, header_errors) = validate_headers(header_buf);
    let header_formats: Vec<Format> = verdicts.iter().map(|v| v.format).collect();

    // Phase 3: Heuristic analysis (entropy, endianness, architecture)
    let (ea, entropy_overall, (e_guess, e_conf), arch_guesses) = analyze_heuristics(heur_buf);
    let entropy = Some(ea.summary.clone());

    // Phase 4: String extraction
    let strings = extract_strings(heur_buf, strings_cfg, &hints, entropy_overall);

    // Phase 5: Parser probes and container/packer discovery
    debug!(phase = "parsers", "structured parse probes");
    let parser_results = parsers::parse(heur_buf);
    let (mut containers, rec_depth, _packers_placeholder) =
        discover_containers_and_packers(heur_buf, &hints, max_recursion_depth);
    // Compute packers here with provided config
    let packers = {
        let v = detect_packers(heur_buf, packer_cfg);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };

    // Ensure deterministic ordering of children if present
    if let Some(ref mut vv) = containers {
        vv.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.type_name.cmp(&b.type_name)));
    }

    // Phase 6: Error merging
    let container_labels: Vec<String> = containers
        .as_ref()
        .map(|v| v.iter().map(|c| c.type_name.clone()).collect())
        .unwrap_or_default();
    let merged_errors = merge_errors(
        sniff_errors,
        header_errors,
        &hints,
        &header_formats,
        &container_labels,
        hit_byte_limit,
        limit_bytes,
        initial_bytes_read,
    );

    // Phase 7: Artifact construction and scoring
    let looks_exec =
        !header_formats.is_empty() || hints.iter().any(|h| derive_format_from_hint(h).is_some());

    // Optional disassembly preview (bounded, budgeted): only if likely executable
    let disasm_preview = if looks_exec {
        compute_disasm_preview(heur_buf, &arch_guesses, e_guess, 32, 512, 5)
    } else {
        None
    };

    // Format-specific analysis
    let format_specific = if header_formats.first().copied() == Some(Format::PE) {
        let rich_header = crate::triage::rich_header::parse_rich_header(heur_buf);
        Some(FormatSpecificTriage {
            pe: Some(PeTriageInfo { rich_header }),
            ..Default::default()
        })
    } else {
        None
    };

    // Compute symbol summary, using heuristics buffer (bounded to MAX_ENTROPY_SIZE)
    let symbols_sum = header_formats
        .first()
        .map(|fmt| symbols::summarize_symbols(heur_buf, *fmt, &BudgetCaps::default()));

    // Detect overlay data if we have a recognized binary format
    let overlay = header_formats
        .first()
        .and_then(|fmt| crate::triage::overlay::detect_overlay(heur_buf, *fmt));

    // Compute similarity summary (CTPH for all; imphash for PE if available)
    let similarity = {
        // imphash only for PE, else None
        let imphash = if header_formats.first().copied() == Some(crate::core::binary::Format::PE) {
            crate::symbols::analysis::imphash::pe_imphash(heur_buf)
        } else {
            None
        };
        // CTPH over bounded heuristics buffer, if enabled
        let ctph = if sim_cfg.enable_ctph {
            let (w, d, p) = if sim_cfg.window_size == 0 || sim_cfg.digest_size == 0 {
                if heur_buf.len() < 16 * 1024 {
                    (8usize, 4usize, 8u8)
                } else if heur_buf.len() < 1 * 1024 * 1024 {
                    (16usize, 5usize, 16u8)
                } else {
                    (32usize, 6usize, 16u8)
                }
            } else {
                (sim_cfg.window_size, sim_cfg.digest_size, sim_cfg.precision)
            };
            let cfg = crate::similarity::CtphConfig {
                window_size: w,
                digest_size: d,
                precision: p,
            };
            Some(crate::similarity::ctph_hash(heur_buf, &cfg))
        } else {
            None
        };
        Some(crate::core::triage::SimilaritySummary { imphash, ctph })
    };

    // Signing summary: surface high-level presence bits
    let signing = {
        use crate::triage::signing::SigningSummary;
        let pe_auth = if header_formats.first().copied() == Some(crate::core::binary::Format::PE) {
            // Heuristic: overlay contains a signature blob
            overlay.as_ref().map(|o| o.has_signature).unwrap_or(false)
        } else {
            false
        };
        let macho_sig = if header_formats.first().copied()
            == Some(crate::core::binary::Format::MachO)
        {
            if let Some(env) = crate::symbols::analysis::macho_env::analyze_macho_env(heur_buf) {
                env.code_signature
            } else {
                false
            }
        } else {
            false
        };
        let macho_ent =
            if header_formats.first().copied() == Some(crate::core::binary::Format::MachO) {
                if crate::symbols::analysis::macho_env::analyze_macho_env(heur_buf).is_some() {
                    // Lightweight heuristic: if rpaths mention entitlements or codesign present and plist markers exist in image
                    macho_sig
                        && std::str::from_utf8(heur_buf)
                            .map(|s| s.contains("Entitlements"))
                            .unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            };
        Some(SigningSummary {
            pe_authenticode_present: pe_auth,
            macho_code_signature_present: macho_sig,
            macho_entitlements_present: macho_ent,
            overlay_has_signature: overlay.as_ref().map(|o| o.has_signature).unwrap_or(false),
        })
    };

    // Build preliminary artifact (pre-scoring) so scoring can consider context
    let recursion_summary = {
        let total = containers.as_ref().map(|v| v.len() as u32).unwrap_or(0);
        let danger = packers.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
        Some(crate::triage::recurse::RecursionSummary {
            total_children: total,
            max_depth: rec_depth,
            dangerous_child_present: danger,
        })
    };

    let prelim = TriagedArtifact::builder()
        .with_schema_version("1.2")
        .with_id(id)
        .with_path(path)
        .with_size_bytes(size_bytes as u64)
        .with_sha256(None::<String>)
        .with_hints(hints)
        .with_verdicts(verdicts)
        .with_entropy(entropy)
        .with_entropy_analysis(Some(ea))
        .with_strings(strings.clone())
        .with_symbols(symbols_sum)
        .with_similarity(similarity)
        .with_signing(signing)
        .with_packers(packers)
        .with_containers(containers)
        .with_recursion_summary(recursion_summary)
        .with_overlay(overlay)
        .with_format_specific(format_specific.clone())
        .with_parse_status(if parser_results.is_empty() {
            None
        } else {
            Some(parser_results.clone())
        })
        .with_budgets(Some(Budgets {
            bytes_read: initial_bytes_read,
            time_ms: t0.elapsed().as_millis() as u64,
            recursion_depth: rec_depth,
            limit_bytes: Some(limit_bytes),
            limit_time_ms: None,
            max_recursion_depth: Some(declared_max_recursion as u32),
            hit_byte_limit,
        }))
        .with_errors(merged_errors.clone())
        .with_heuristic_endianness(if looks_exec {
            Some((e_guess, e_conf))
        } else {
            None
        })
        .with_heuristic_arch(if looks_exec {
            Some(arch_guesses.clone())
        } else {
            None
        })
        .build()
        .expect("All required fields are provided");

    // Score and rank verdicts
    let ranked = score::score(&prelim);

    // Build final artifact with ranked verdicts
    let art = TriagedArtifact::builder()
        .with_id(prelim.id)
        .with_path(prelim.path)
        .with_size_bytes(prelim.size_bytes)
        .with_sha256(prelim.sha256)
        .with_hints(prelim.hints)
        .with_verdicts(ranked)
        .with_entropy(prelim.entropy)
        .with_entropy_analysis(prelim.entropy_analysis)
        .with_strings(strings)
        .with_similarity(prelim.similarity)
        .with_disasm_preview(disasm_preview)
        .with_symbols(prelim.symbols)
        .with_packers(prelim.packers)
        .with_containers(prelim.containers)
        .with_overlay(prelim.overlay)
        .with_format_specific(prelim.format_specific)
        .with_parse_status(prelim.parse_status)
        .with_budgets(Some(Budgets {
            bytes_read: initial_bytes_read,
            time_ms: t0.elapsed().as_millis() as u64,
            recursion_depth: rec_depth,
            limit_bytes: Some(limit_bytes),
            limit_time_ms: None,
            max_recursion_depth: Some(declared_max_recursion as u32),
            hit_byte_limit,
        }))
        .with_errors(merged_errors)
        .with_heuristic_endianness(if looks_exec {
            prelim.heuristic_endianness
        } else {
            None
        })
        .with_heuristic_arch(if looks_exec {
            prelim.heuristic_arch
        } else {
            None
        })
        .build()
        .expect("All required fields are provided");

    info!("complete");
    art
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests_inner {
    use super::*;
    use crate::core::triage::Budgets;
    use crate::triage::recurse::RecursionEngine;
    use crate::triage::sniffers::CombinedSniffer;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[test]
    fn header_vs_sniffer_mismatch_on_elf_with_exe_extension() {
        let path =
            PathBuf::from("samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return,
        }; // skip if absent
        let sniff_buf = &data[..data.len().min(crate::triage::io::MAX_SNIFF_SIZE as usize)];
        let header_buf = &data[..data.len().min(crate::triage::io::MAX_HEADER_SIZE as usize)];
        let sn = CombinedSniffer::sniff(sniff_buf, Some(Path::new("fake.exe")));
        let hdr = crate::triage::headers::validate(header_buf);
        let header_formats: Vec<Format> = hdr.candidates.iter().map(|v| v.format).collect();
        assert!(header_formats.contains(&Format::ELF));
        let errs = compute_sniffer_header_mismatches(&sn.hints, &header_formats, &[]);
        // Expect at least one mismatch due to exe extension vs ELF header
        assert!(!errs.is_empty());
        assert!(errs
            .iter()
            .any(|e| e.kind == TriageErrorKind::SnifferMismatch));
    }

    #[test]
    fn container_hint_exemption_for_zip_with_exe_extension() {
        // Use a real ZIP from samples; pretend it's named .exe to trigger extension conflict
        let path = PathBuf::from("samples/containers/zip/hello-cpp-g++-O0.zip");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let sniff_buf = &data[..data.len().min(crate::triage::io::MAX_SNIFF_SIZE as usize)];
        let header_buf = &data[..data.len().min(crate::triage::io::MAX_HEADER_SIZE as usize)];
        let sn = CombinedSniffer::sniff(sniff_buf, Some(Path::new("fake.exe")));
        let hdr = crate::triage::headers::validate(header_buf);
        let header_formats: Vec<Format> = hdr.candidates.iter().map(|v| v.format).collect();
        // Discover containers to feed exemptions
        let engine = RecursionEngine::default();
        let mut tmp_budget = Budgets::new(data.len() as u64, 0, 0);
        let containers = engine.discover_children(&data, &mut tmp_budget, 0);
        let container_labels: Vec<String> = containers.into_iter().map(|c| c.type_name).collect();
        let errs = compute_sniffer_header_mismatches(&sn.hints, &header_formats, &container_labels);
        // With no validated headers and a matching container hint, do not emit a mismatch
        assert!(errs.is_empty());
    }

    #[test]
    fn non_binary_png_classifies_safely() {
        let path = PathBuf::from("assets/glaurung-original.png");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let sniff_buf = &data[..data.len().min(crate::triage::io::MAX_SNIFF_SIZE as usize)];
        let header_buf = &data[..data.len().min(crate::triage::io::MAX_HEADER_SIZE as usize)];
        let sn = CombinedSniffer::sniff(sniff_buf, Some(&path));
        // Expect an image/png label
        assert!(sn
            .hints
            .iter()
            .any(|h| h.mime.as_deref() == Some("image/png")));
        let hdr = crate::triage::headers::validate(header_buf);
        // Expect no executable header candidates
        assert!(hdr.candidates.is_empty());
        // No mismatches computed if there are no headers
        let errs = compute_sniffer_header_mismatches(&sn.hints, &[], &[]);
        assert!(errs.is_empty());
    }

    #[test]
    fn budgets_are_tracked_in_analyze_bytes() {
        let data = vec![0u8; 32 * 1024];
        let limits = IOLimits {
            max_read_bytes: 8 * 1024, // bound entropy slice
            max_file_size: u64::MAX,
        };
        let art = analyze_bytes(&data, &limits).expect("analyze_bytes");
        let b = art.budgets.expect("budgets present");
        // sniff(4K) + header(64K capped to data) + entropy(8K)
        let expected_header = (data.len().min(MAX_HEADER_SIZE as usize)) as u64;
        let expected = MAX_SNIFF_SIZE + expected_header + (8 * 1024) as u64;
        assert_eq!(b.bytes_read, expected);
        assert!(b.time_ms <= 1000, "analysis took too long: {}ms", b.time_ms);
        assert!(b.recursion_depth <= 1);
        // With small max_read_bytes, we should mark hit_byte_limit
        assert!(b.hit_byte_limit, "expected hit_byte_limit to be true");
    }

    #[test]
    fn hit_byte_limit_is_false_when_limits_are_high() {
        let data = vec![0u8; 8 * 1024];
        let limits = IOLimits {
            max_read_bytes: 10 * 1024 * 1024, // much larger than data and phases
            max_file_size: u64::MAX,
        };
        let art = analyze_bytes(&data, &limits).expect("analyze_bytes");
        let b = art.budgets.expect("budgets present");
        assert!(!b.hit_byte_limit);
        assert_eq!(b.limit_bytes, Some(limits.max_read_bytes));
    }
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_path")]
#[pyo3(signature = (
    path,
    _max_read_bytes=10_485_760,
    _max_file_size=104_857_600,
    _max_recursion_depth=1,
    _min_string_length=4,
    _max_string_samples=40,
    _enable_language=true,
    _max_lang_detect=100,
    _enable_classification=true,
    _max_classify=200,
    _max_ioc_per_string=16,
    _config=None
))]
pub fn analyze_path_py(
    path: String,
    _max_read_bytes: u64,
    _max_file_size: u64,
    _max_recursion_depth: usize,
    _min_string_length: usize,
    _max_string_samples: usize,
    _enable_language: bool,
    _max_lang_detect: usize,
    _enable_classification: bool,
    _max_classify: usize,
    _max_ioc_per_string: usize,
    _config: Option<TriageConfig>,
) -> PyResult<TriagedArtifact> {
    let p = Path::new(&path);
    let limits = IOLimits {
        max_read_bytes: _max_read_bytes,
        max_file_size: _max_file_size,
    };
    let mut reader = SafeFileReader::open(p, limits.clone())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    if reader.size() == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty file"));
    }
    let sniff = reader
        .read_prefix(MAX_SNIFF_SIZE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    let header = reader
        .read_prefix(MAX_HEADER_SIZE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    let heur = reader
        .read_prefix(MAX_ENTROPY_SIZE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    let bytes_read = sniff.len() as u64 + header.len() as u64 + heur.len() as u64;
    // detect if any prefix was capped by byte limit
    let file_size = reader.size();
    let cap = limits.max_read_bytes;
    let hit_byte_limit = file_size > cap
        && (sniff.len() as u64 == cap
            || header.len() as u64 == cap
            || heur.len() as u64 == cap
            || MAX_SNIFF_SIZE > cap
            || MAX_HEADER_SIZE > cap
            || MAX_ENTROPY_SIZE > cap);
    let strings_cfg = StringsConfig {
        min_length: _min_string_length,
        max_samples: _max_string_samples,
        max_scan_bytes: MAX_ENTROPY_SIZE as usize,
        time_guard_ms: 10,
        enable_language: _enable_language,
        max_lang_detect: _max_lang_detect,
        min_len_for_detect: 4,
        max_len_for_lingua: 32,
        min_lang_confidence: 0.5,
        min_lang_confidence_agree: 0.4,
        texty_strict: false,
        use_fast_detection: true,
        enable_classification: _enable_classification,
        max_classify: _max_classify,
        max_ioc_per_string: _max_ioc_per_string,
        max_ioc_samples: 50,
    };
    let packer_cfg: PackerConfig = _config
        .as_ref()
        .map(|c| c.packers.clone())
        .unwrap_or_else(PackerConfig::default);
    let sim_cfg: SimilarityConfig = _config
        .as_ref()
        .map(|c| c.similarity.clone())
        .unwrap_or_else(SimilarityConfig::default);
    Ok(build_artifact_from_buffers(
        path,
        reader.size() as usize,
        &sniff,
        &header,
        &heur,
        _max_recursion_depth,
        bytes_read,
        limits.max_read_bytes,
        _max_recursion_depth,
        hit_byte_limit,
        &strings_cfg,
        &packer_cfg,
        &sim_cfg,
    ))
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_bytes")]
#[pyo3(signature = (
    data,
    max_read_bytes=10_485_760,
    max_recursion_depth=1,
    min_string_length=4,
    max_string_samples=40,
    enable_language=true,
    max_lang_detect=100,
    enable_classification=true,
    max_classify=200,
    max_ioc_per_string=16,
    config=None
))]
pub fn analyze_bytes_py(
    data: Vec<u8>,
    max_read_bytes: u64,
    max_recursion_depth: usize,
    min_string_length: usize,
    max_string_samples: usize,
    enable_language: bool,
    max_lang_detect: usize,
    enable_classification: bool,
    max_classify: usize,
    max_ioc_per_string: usize,
    config: Option<TriageConfig>,
) -> PyResult<TriagedArtifact> {
    if data.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty data"));
    }
    let sniff_len = data.len().min(MAX_SNIFF_SIZE as usize);
    let header_len = data.len().min(MAX_HEADER_SIZE as usize);
    let ent_len = data.len().min(MAX_ENTROPY_SIZE as usize);
    let bytes_read = (sniff_len + header_len + ent_len) as u64;
    let cap = max_read_bytes;
    let data_len = data.len() as u64;
    let hit_byte_limit = data_len > cap
        && (sniff_len as u64 == cap
            || header_len as u64 == cap
            || ent_len as u64 == cap
            || MAX_SNIFF_SIZE > cap
            || MAX_HEADER_SIZE > cap
            || MAX_ENTROPY_SIZE > cap);
    let strings_cfg = StringsConfig {
        min_length: min_string_length,
        max_samples: max_string_samples,
        max_scan_bytes: ent_len,
        time_guard_ms: 10,
        enable_language,
        max_lang_detect,
        min_len_for_detect: 4,
        max_len_for_lingua: 32,
        min_lang_confidence: 0.5,
        min_lang_confidence_agree: 0.4,
        texty_strict: false,
        use_fast_detection: true,
        enable_classification,
        max_classify,
        max_ioc_per_string,
        max_ioc_samples: 50,
    };
    let packer_cfg: PackerConfig = config
        .as_ref()
        .map(|c| c.packers.clone())
        .unwrap_or_else(PackerConfig::default);
    let sim_cfg: SimilarityConfig = config
        .as_ref()
        .map(|c| c.similarity.clone())
        .unwrap_or_else(SimilarityConfig::default);
    Ok(build_artifact_from_buffers(
        "<memory>".to_string(),
        data.len(),
        &data[..sniff_len],
        &data[..header_len],
        &data[..ent_len],
        max_recursion_depth,
        bytes_read,
        max_read_bytes,
        max_recursion_depth,
        hit_byte_limit,
        &strings_cfg,
        &packer_cfg,
        &sim_cfg,
    ))
}

/// Pure Rust API: analyze a file path with I/O limits.
pub fn analyze_path<P: AsRef<Path>>(
    path: P,
    limits: &IOLimits,
) -> std::io::Result<TriagedArtifact> {
    let p = path.as_ref();
    let mut reader = SafeFileReader::open(p, limits.clone())?;
    if reader.size() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Empty file",
        ));
    }
    let sniff = reader.read_prefix(MAX_SNIFF_SIZE)?;
    let header = reader.read_prefix(MAX_HEADER_SIZE)?;
    let heur = reader.read_prefix(MAX_ENTROPY_SIZE)?;
    let bytes_read = sniff.len() as u64 + header.len() as u64 + heur.len() as u64;
    let cap = limits.max_read_bytes;
    let file_size = reader.size();
    let hit_byte_limit = file_size > cap
        && (sniff.len() as u64 == cap
            || header.len() as u64 == cap
            || heur.len() as u64 == cap
            || MAX_SNIFF_SIZE > cap
            || MAX_HEADER_SIZE > cap
            || MAX_ENTROPY_SIZE > cap);
    let strings_cfg = StringsConfig::default();
    Ok(build_artifact_from_buffers(
        p.to_string_lossy().into_owned(),
        reader.size() as usize,
        &sniff,
        &header,
        &heur,
        1,
        bytes_read,
        limits.max_read_bytes,
        1,
        hit_byte_limit,
        &strings_cfg,
        &PackerConfig::default(),
        &SimilarityConfig::default(),
    ))
}

/// Pure Rust API: analyze raw bytes with I/O limits (only used for budgets; limits.max_read_bytes bounds processing).
pub fn analyze_bytes(data: &[u8], limits: &IOLimits) -> std::io::Result<TriagedArtifact> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Empty data",
        ));
    }
    let sniff_len = data.len().min(MAX_SNIFF_SIZE as usize);
    let header_len = data.len().min(MAX_HEADER_SIZE as usize);
    let ent_bound = limits.max_read_bytes.min(MAX_ENTROPY_SIZE) as usize;
    let ent_len = data.len().min(ent_bound);
    let bytes_read = (sniff_len + header_len + ent_len) as u64;
    let cap = limits.max_read_bytes;
    let data_len = data.len() as u64;
    let hit_byte_limit = data_len > cap
        && (sniff_len as u64 == cap
            || header_len as u64 == cap
            || ent_len as u64 == cap
            || ent_bound as u64 == cap
            || MAX_SNIFF_SIZE > cap
            || MAX_HEADER_SIZE > cap);
    let strings_cfg = StringsConfig::default();
    Ok(build_artifact_from_buffers(
        "<memory>".to_string(),
        data.len(),
        &data[..sniff_len],
        &data[..header_len],
        &data[..ent_len],
        1,
        bytes_read,
        limits.max_read_bytes,
        1,
        hit_byte_limit,
        &strings_cfg,
        &PackerConfig::default(),
        &SimilarityConfig::default(),
    ))
}
