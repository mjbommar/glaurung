//! Export one source-bound proof-carrying Glaurung infeasible-path verdict.
//!
//! This is a downstream consumer demonstration, not a solver benchmark or a
//! whole-CFG unreachability proof. The attached DRAT checks the emitted CNF;
//! `recheck_for_path` additionally binds that CNF to the exact Glaurung path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use glaurung::ir::types::{CmpOp, Width};
use glaurung::symbolic::expr::{Expr, ExprId, ExprPool};
use glaurung::symbolic::solver::axeyum_backend::{
    AxeyumSolver, InfeasiblePathCertificate, InfeasiblePathVerdict,
};
use glaurung::symbolic::solver::Assert;
use serde::Serialize;
use sha2::{Digest, Sha256};

const SCHEMA: &str = "glaurung-infeasible-path-proof-v1";
const PATH_ID: &str = "glaurung-expr-x-eq-5-and-x-eq-6-v1";

#[derive(Debug, Serialize)]
struct FileRecord {
    path: &'static str,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct BundleManifest {
    schema: &'static str,
    path_id: &'static str,
    verdict: &'static str,
    assertion_count: usize,
    source_rechecked: bool,
    proof_scope: &'static str,
    dimacs: FileRecord,
    drat: FileRecord,
    lrat: Option<FileRecord>,
}

fn constant(pool: &mut ExprPool, value: u128, width: Width) -> ExprId {
    pool.intern(Expr::Const { value, width })
}

fn equal(pool: &mut ExprPool, left: ExprId, right: ExprId, width: Width) -> ExprId {
    pool.intern(Expr::Cmp {
        op: CmpOp::Eq,
        a: left,
        b: right,
        width,
    })
}

fn fixed_path() -> (ExprPool, Vec<Assert>) {
    let mut pool = ExprPool::new();
    let width = Width::W32;
    let input = pool.fresh_symbol(width);
    let five = constant(&mut pool, 5, width);
    let six = constant(&mut pool, 6, width);
    let equals_five = equal(&mut pool, input, five, width);
    let equals_six = equal(&mut pool, input, six, width);
    (pool, vec![(equals_five, true), (equals_six, true)])
}

fn fixed_certificate() -> Result<(ExprPool, Vec<Assert>, InfeasiblePathCertificate)> {
    let (pool, path) = fixed_path();
    let certificate = match AxeyumSolver::new().prove_infeasible_path(&pool, &path) {
        InfeasiblePathVerdict::Infeasible(certificate) => certificate,
        InfeasiblePathVerdict::Feasible => bail!("fixed path unexpectedly feasible"),
        InfeasiblePathVerdict::Inconclusive => bail!("fixed path proof search inconclusive"),
        InfeasiblePathVerdict::Error(error) => bail!("fixed path proof failed: {error}"),
    };
    if !certificate
        .recheck_for_path(&pool, &path)
        .map_err(anyhow::Error::msg)?
    {
        bail!("fixed path certificate failed its source-bound recheck");
    }
    Ok((pool, path, certificate))
}

fn file_record(path: &'static str, bytes: &[u8]) -> FileRecord {
    FileRecord {
        path,
        bytes: bytes.len(),
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn write_new_bundle(
    output_dir: &Path,
    assertion_count: usize,
    certificate: &InfeasiblePathCertificate,
) -> Result<()> {
    std::fs::create_dir(output_dir)
        .with_context(|| format!("create new proof output directory {}", output_dir.display()))?;

    let dimacs = certificate.dimacs().as_bytes();
    let drat = certificate.drat().as_bytes();
    std::fs::write(output_dir.join("problem.cnf"), dimacs).context("write proof problem.cnf")?;
    std::fs::write(output_dir.join("proof.drat"), drat).context("write proof.drat")?;

    let lrat = if let Some(text) = certificate.lrat() {
        let bytes = text.as_bytes();
        std::fs::write(output_dir.join("proof.lrat"), bytes).context("write proof.lrat")?;
        Some(file_record("proof.lrat", bytes))
    } else {
        None
    };
    let manifest = BundleManifest {
        schema: SCHEMA,
        path_id: PATH_ID,
        verdict: "infeasible",
        assertion_count,
        source_rechecked: true,
        proof_scope: "CNF unsat; Glaurung path is deterministically rebound to CNF; term-to-AIG-to-CNF remains the documented trusted reduction",
        dimacs: file_record("problem.cnf", dimacs),
        drat: file_record("proof.drat", drat),
        lrat,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).context("serialize manifest")?;
    std::fs::write(output_dir.join("manifest.json"), manifest_bytes)
        .context("write manifest.json")?;
    Ok(())
}

fn output_argument() -> Result<PathBuf> {
    let mut args = std::env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| OsString::from("axeyum_infeasible_path_proof"));
    let Some(output) = args.next() else {
        bail!("usage: {} OUTPUT_DIR", Path::new(&program).display());
    };
    if args.next().is_some() {
        bail!("usage: {} OUTPUT_DIR", Path::new(&program).display());
    }
    Ok(PathBuf::from(output))
}

fn main() -> Result<()> {
    let output_dir = output_argument()?;
    let (_pool, path, certificate) = fixed_certificate()?;
    write_new_bundle(&output_dir, path.len(), &certificate)?;
    println!("{}", output_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_source_bound_bundle_with_matching_manifest() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let output = temp.path().join("bundle");
        let (_pool, path, certificate) = fixed_certificate().expect("fixed certificate");
        write_new_bundle(&output, path.len(), &certificate).expect("write proof bundle");

        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join("manifest.json")).expect("manifest bytes"),
        )
        .expect("manifest JSON");
        assert_eq!(manifest["schema"], SCHEMA);
        assert_eq!(manifest["verdict"], "infeasible");
        assert_eq!(manifest["assertion_count"], 2);
        assert_eq!(manifest["source_rechecked"], true);
        for (field, file) in [("dimacs", "problem.cnf"), ("drat", "proof.drat")] {
            let bytes = std::fs::read(output.join(file)).expect("proof file");
            assert_eq!(manifest[field]["bytes"], bytes.len());
            assert_eq!(
                manifest[field]["sha256"],
                hex::encode(Sha256::digest(&bytes))
            );
        }
    }

    #[test]
    fn refuses_an_existing_output_directory() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let output = temp.path().join("existing");
        std::fs::create_dir(&output).expect("existing output directory");
        let (_pool, path, certificate) = fixed_certificate().expect("fixed certificate");
        let error = write_new_bundle(&output, path.len(), &certificate)
            .expect_err("existing output must be refused");
        assert!(error
            .to_string()
            .contains("create new proof output directory"));
    }
}
