//! Marcelli's task taxonomy, adapted to the free variables this corpus has.
//!
//! # What the corpus can and cannot vary
//!
//! `tests/decompiler_fixtures/build/` varies exactly two things while keeping
//! symbols: the compiler (`gcc`, `clang`) and the optimisation level (`O0`,
//! `O2`). It is one architecture, one bitness, one platform. So of Marcelli's
//! seven tasks this harness can run **XO** (cross-optimisation), **XC**
//! (cross-compiler), **XM** (both free) and the three XM size strata. XA
//! (cross-architecture), XB (cross-bitness) and XC+XB have no lane here and
//! are marked as such rather than silently omitted -- they arrive with the
//! `--arch` fixture matrix or with BinKit ingestion (plan item 9).
//!
//! # Negative sampling discipline
//!
//! Marcelli names loose negatives as a frequent, silent source of inflated
//! published results: "in XO, the negative shares the architecture". Here that
//! discipline is structural rather than a rule someone has to remember --
//! every negative for a task is drawn from that task's **pool slice**, so a
//! cross-optimisation negative necessarily shares the compiler and a
//! cross-compiler negative necessarily shares the optimisation level. There is
//! no code path that can draw one from anywhere else.

use crate::corpus::FunctionSample;

/// A size stratum, applied to the QUERY function's basic-block count.
///
/// Block counts, not byte counts: that is what Marcelli strata on, and it is
/// the number the `<5 blocks` filter already made everyone look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stratum {
    /// XM-S: fewer than 20 basic blocks.
    Small,
    /// XM-M: 20 to 100 basic blocks, inclusive.
    Medium,
    /// XM-L: more than 100 basic blocks.
    Large,
}

impl Stratum {
    pub fn contains(self, sample: &FunctionSample) -> bool {
        let n = sample.block_count();
        match self {
            Stratum::Small => n < 20,
            Stratum::Medium => (20..=100).contains(&n),
            Stratum::Large => n > 100,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Stratum::Small => "<20 blocks",
            Stratum::Medium => "20-100 blocks",
            Stratum::Large => ">100 blocks",
        }
    }
}

/// One retrieval task: a query slice, a pool slice, and what varies between
/// them.
#[derive(Clone, Copy, Debug)]
pub struct Task {
    /// Marcelli's name, suffixed where this corpus splits a task in two.
    pub name: &'static str,
    /// `(compiler, opt)` the query functions come from.
    pub query: (&'static str, &'static str),
    /// `(compiler, opt)` the candidate pool comes from.
    pub pool: (&'static str, &'static str),
    /// The compilation variables that are free between query and pool. Printed
    /// with every number, because a number without it is not comparable to
    /// anything.
    pub free_variables: &'static str,
    /// Restrict the queries to one size band.
    pub stratum: Option<Stratum>,
}

impl Task {
    pub fn accepts(&self, sample: &FunctionSample) -> bool {
        self.stratum.is_none_or(|s| s.contains(sample))
    }

    /// The free-variable set as it should be printed, stratum included.
    pub fn conditions(&self) -> String {
        let base = format!(
            "{} -> {} (free: {})",
            slice_label(self.query),
            slice_label(self.pool),
            self.free_variables
        );
        match self.stratum {
            Some(s) => format!("{base}, queries {}", s.label()),
            None => base,
        }
    }
}

fn slice_label((compiler, opt): (&str, &str)) -> String {
    format!("{compiler}/{opt}")
}

/// The default lane: every task the corpus supports.
///
/// Order is fixed so the JSON report and the printed log are stable.
pub const TASKS: &[Task] = &[
    Task {
        name: "XO-gcc",
        query: ("gcc", "O0"),
        pool: ("gcc", "O2"),
        free_variables: "optimisation",
        stratum: None,
    },
    Task {
        name: "XO-clang",
        query: ("clang", "O0"),
        pool: ("clang", "O2"),
        free_variables: "optimisation",
        stratum: None,
    },
    Task {
        name: "XC-O0",
        query: ("gcc", "O0"),
        pool: ("clang", "O0"),
        free_variables: "compiler",
        stratum: None,
    },
    Task {
        name: "XC-O2",
        query: ("gcc", "O2"),
        pool: ("clang", "O2"),
        free_variables: "compiler",
        stratum: None,
    },
    Task {
        name: "XM",
        query: ("gcc", "O0"),
        pool: ("clang", "O2"),
        free_variables: "compiler + optimisation",
        stratum: None,
    },
    Task {
        name: "XM-S",
        query: ("gcc", "O0"),
        pool: ("clang", "O2"),
        free_variables: "compiler + optimisation",
        stratum: Some(Stratum::Small),
    },
    Task {
        name: "XM-M",
        query: ("gcc", "O0"),
        pool: ("clang", "O2"),
        free_variables: "compiler + optimisation",
        stratum: Some(Stratum::Medium),
    },
    Task {
        name: "XM-L",
        query: ("gcc", "O0"),
        pool: ("clang", "O2"),
        free_variables: "compiler + optimisation",
        stratum: Some(Stratum::Large),
    },
];

/// Tasks this corpus CANNOT express, recorded so their absence is a stated
/// gap rather than an unexamined one.
///
/// Written into every JSON report next to the tasks that did run.
/// **These lanes now exist elsewhere.** `cisco.rs` runs XA, XB, XA+XB and
/// XA+XO over Cisco Talos Dataset-1, which varies architecture, bitness,
/// compiler, compiler version and optimisation. What follows is what *this*
/// corpus cannot express, which is still worth recording next to every result
/// computed over it: a reader of a fixture-corpus report should not have to
/// know that a second corpus exists to know that this one is x86-64 only.
pub const UNSUPPORTED_TASKS: &[(&str, &str)] = &[
    (
        "XA",
        "cross-architecture: the build directory is x86-64 only. Run over \
         Cisco Talos Dataset-1 instead (tests/identity_retrieval/cisco.rs, \
         GLAURUNG_CISCO_CORPUS), which has six architecture/bitness \
         combinations. The `dectest --arch` matrix (i386, armv7, aarch64) is \
         the route to an in-house lane if one is wanted.",
    ),
    (
        "XB",
        "cross-bitness: needs the i386 lane of the same matrix. Shi et al. \
         name this as the task that separates IR representations from token \
         representations. Runs on Dataset-1 as the `XB` task \
         (x64-gcc-9-O2 -> x86-gcc-9-O2).",
    ),
    (
        "XC+XB",
        "compiler and bitness both free. Dataset-1 ships published pair files \
         for exactly this task; see cisco::PublishedPairPool.",
    ),
    (
        "XA+XO",
        "architecture and optimisation both free: runs on Dataset-1 as \
         `XA+XO`.",
    ),
    (
        "NoInline",
        "BinKit's -fno-inline lane. Inlining is the field's unsolved failure \
         (82-84% of failures in the best tools), and neither this corpus nor \
         Dataset-1 can isolate it -- Dataset-1 disables inlining throughout. \
         BinKit 2.0 is hundreds of GB and is deliberately not ingested.",
    ),
];
