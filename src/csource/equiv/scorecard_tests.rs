//! The separation gate: sensitivity and specificity per mutation class.
//!
//! `roadmap.md` section 7 states the gate for this stage as separation, not
//! coverage --- a known-good and a known-bad decompilation must come back with
//! different verdicts. Hand-picked pairs cannot establish that: a checker that
//! answers "different" to everything separates every hand-picked pair and is
//! worthless. So the validation set is
//! [`tools/metric_mutation.py`](../../../tools/metric_mutation.py)'s catalogue,
//! whose 15 semantics-changing and 14 semantics-preserving classes carry a
//! ground-truth label and a written justification for it, and which is the same
//! instrument that measured GED at 21.8% sensitivity / 95.3% specificity.
//!
//! `tools/equiv_mutants.py` applies that catalogue to the fixture functions the
//! S4 lowering covers and writes the pairs to
//! `tests/csource_equiv/mutants.jsonl`. The corpus is generated and gitignored,
//! like `tests/decompiler_fixtures/build/`, and its absence is a **visible**
//! skip rather than a quiet pass.
//!
//! # What is and is not counted
//!
//! Three outcomes, three columns, and the third is never folded into either of
//! the first two:
//!
//! * `Different` --- the checker flagged the mutant. A true positive on a
//!   changing class, a false alarm on a preserving one.
//! * `Equivalent` --- the checker cleared it. A false negative on a changing
//!   class, a true negative on a preserving one.
//! * `Unknown` --- the checker abstained, with a reason. Reported as a rate,
//!   excluded from both ratios, and printed with its reason breakdown so an
//!   abstention rate cannot be mistaken for a score.
//!
//! A pair whose original or mutant the lowering refuses is a **decline**, not an
//! abstention: the checker was never asked.
//!
//! # A label is not the truth, and this measured the difference
//!
//! The catalogue's labels are per *class*, and every class that can be
//! mislabelled on an instance says so in its own `caveat` --- "no effect if the
//! literal sits on dead code", "only observable on an input that hits the
//! boundary value". At the seed and corpus recorded below, **17 cells** were
//! labelled behaviour-changing and came back `Equivalent`. All 17 were read by
//! hand: sixteen are genuine equivalences and the seventeenth was this checker
//! being wrong. Both halves of that sentence are the point, so both are written
//! down here.
//!
//! The sixteen it got right:
//!
//! * `select_max`, `chained_selects`, `early_out_branchless`,
//!   `nested_conditional_matrix` --- `a > b ? a : b` versus `a >= b ? a : b`.
//!   The predicate changes at `a == b`; the *function* does not, because both
//!   arms return the same value there.
//! * `sub_then_sign` (`d < 0` to `d <= 0` and to `d < 1`) --- at `d == 0`,
//!   `-d == d`.
//! * `dec_preserves_carry` (`a < b` to `a <= b`) --- at `a == b`, `d + i` and
//!   `i` are both 2 because `d` is 0.
//! * `plain_char_is_signed` --- `probe` is `(char)0x80`, so `< 0`, `<= 0` and
//!   `< 1` all hold.
//! * `median_of_three` --- the rewrite changes *which* branch returns, and both
//!   branches return the same value.
//! * `fixed_divide` (`< INT_MIN` to `<= INT_MIN`) --- the clamp and the
//!   fall-through produce the same `INT_MIN`.
//! * `wraps_to_zero` (`value + (0u - value)`) and `maximum_plus_one`
//!   (`0xFFFFFFFFu + 1u`) versus `return 0;` --- both originals *are* zero.
//! * `division_truncates_toward_zero` --- the bumped literal makes the
//!   `INT_MIN / -1` guard unreachable, and at that input the unguarded body
//!   computes `INT_MIN * 100 + 0`, which is exactly 0 modulo 2^32. Confirmed
//!   concretely.
//!
//! And the one it got wrong, which is why [`VERIFIED_EQUIVALENT`] names cells
//! individually instead of tolerating a percentage of them:
//!
//! * `modular_exponent_of_two` (`> 31` to `> 32`) --- at `exponent == 32` the
//!   mutant evaluates `1u << 32`. A gcc 15.2.0 binary returns 1 there and the
//!   original returns 0, at both `-O0` and `-O1`, so the two are **not**
//!   equivalent. This checker said they were, because the lowering evaluated
//!   the shift on a 64-bit temporary and renormalized afterwards, giving 0 on
//!   both sides. The note that used to stand here called the cell "confirmed
//!   concretely, not only symbolically" --- but that concrete confirmation ran
//!   our own emulator, which shared the same defect, and a second translation
//!   of one mistake is not a confirmation of anything. A compiler is.
//!   `src/csource/lower/expr.rs` now masks the shift count to the promoted
//!   operand width, which closes the cell and, separately, emptied
//!   `KNOWN_UB_DIVERGENCES` in the S4 differential.
//!
//! So the sensitivity figure this test prints is a **floor**: over the audited
//! cells the checker was right sixteen times out of seventeen, including twice
//! where being right required a fact about wrapping arithmetic that no reading
//! of the diff gives you. That is the whole point of a semantic oracle, and it is also why the
//! assertion below is not "zero false negatives" --- that assertion would
//! demand the checker agree with a label its own evidence disproves.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::csource::lower::lower_named_function;

use super::{check_lowered, Bounds, Unknown, Verdict};

/// The generated corpus, or `None` when it has not been built.
fn corpus_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/csource_equiv/mutants.jsonl");
    path.is_file().then_some(path)
}

/// Mutants the catalogue labels behaviour-changing that are in fact equivalent.
///
/// `tools/metric_mutation.py`'s `CATALOGUE` labels a *class*, and every
/// instance inherits that label. That is the right default --- relaxing a
/// relational operator usually does change behaviour --- but a class label is a
/// prediction about a rewrite, not ground truth about the function the rewrite
/// landed in. Deciding whether a given mutant is equivalent is the
/// equivalent-mutant problem, undecidable in general, and *finding* one is this
/// checker working rather than failing.
///
/// So the gate is not "no behaviour-changing mutant is ever proved equivalent".
/// It is "no mutant is proved equivalent unless someone read the pair and
/// agreed". Each entry was verified by reading the diff, and the reason is
/// recorded so the next reader can check the claim instead of trusting it.
///
/// This list is deliberately *not* a percentage floor. A floor of "90% of
/// changing mutants must be caught" passes with a real unsoundness inside it,
/// which is exactly what happened here: of the seventeen cells this sweep first
/// produced, sixteen were genuine equivalences and one --- `constant-bump` on
/// `117_modular_arithmetic.c::modular_exponent_of_two` --- was a false
/// `Equivalent` caused by the `bvshl`-versus-concrete shift mismatch described
/// in the module docs. It is absent from this list on purpose.
const VERIFIED_EQUIVALENT: &[(&str, &str, &str)] = &[
    (
        "arith-flip",
        "208_flag_register_roundtrip.c::control_without_barrier",
        "`product + 0` against `product - 0`: adding and subtracting zero agree",
    ),
    (
        "constant-bump",
        "14_flag_effects.c::sub_then_sign",
        "`d < 0` against `d < 1` differ only at d == 0, where the taken arm returns -0 == 0",
    ),
    (
        "constant-bump",
        "97_signed_unsigned_pitfalls.c::division_truncates_toward_zero",
        "`-2147483648 - 1` is -2147483649 at `long`, because the literal 2147483648 does \
         not fit `int`, so the mutant's second guard clause is unreachable. At \
         INT32_MIN / -1 the unguarded fallthrough computes INT_MIN * 100, and \
         -2^31 * 100 = -2^33 * 25 is an exact multiple of 2^32, so it wraps to 0 --- \
         which is what the guarded original returns",
    ),
    (
        "constant-bump",
        "99_char_and_endianness.c::plain_char_is_signed",
        "probe is (char)0x80 == -128, so `< 0` and `< 1` are both true",
    ),
    (
        "null-body",
        "117_modular_arithmetic.c::wraps_to_zero",
        "`value + (0u - value)` is 0 for every uint32, which is what the stub returns",
    ),
    (
        "null-body",
        "117_modular_arithmetic.c::maximum_plus_one",
        "0xFFFFFFFFu + 1u wraps to 0, which is what the stub returns",
    ),
    (
        "off-by-one",
        "01_conditional_polarity.c::classify",
        "`a < b` against `a <= b`: at a == b the mutant returns b - a == 0 and the \
         original falls through to `return 0`",
    ),
    (
        "off-by-one",
        "131_obfuscated_composite.c::nested_conditional_matrix",
        "`c < d` against `c <= d`: at c == d the two selected arms are the same expression",
    ),
    (
        "off-by-one",
        "14_flag_effects.c::sub_then_sign",
        "`d < 0` against `d <= 0` differ only at d == 0, where -0 == 0",
    ),
    (
        "off-by-one",
        "14_flag_effects.c::dec_preserves_carry",
        "`a < b` against `a <= b`: at a == b the difference d is 0, so d + i == i",
    ),
    (
        "off-by-one",
        "213_arm_predicated_execution.c::select_max",
        "`a > b` against `a >= b`: at a == b both arms are the same value",
    ),
    (
        "off-by-one",
        "213_arm_predicated_execution.c::chained_selects",
        "`b > r` against `b >= r`: at b == r both arms select the same value",
    ),
    (
        "off-by-one",
        "213_arm_predicated_execution.c::early_out_branchless",
        "`a > b` against `a >= b`: at a == b both arms compute 0",
    ),
    (
        "off-by-one",
        "40_quickselect.c::median_of_three",
        "the relaxed clause changes only the a == b case, and the median of (a, a, c) \
         is a on both sides whatever c is",
    ),
    (
        "off-by-one",
        "61_fixed_point.c::fixed_divide",
        "`scaled < -2147483648LL` against `<=`: at scaled == INT32_MIN the mutant \
         returns the saturation constant and the original the identical truncated value",
    ),
    (
        "off-by-one",
        "99_char_and_endianness.c::plain_char_is_signed",
        "probe is (char)0x80 == -128, so `< 0` and `<= 0` are both true",
    ),
];

/// Whether `VERIFIED_EQUIVALENT` covers this cell.
fn is_verified_equivalent(class: &str, unit: &str) -> bool {
    VERIFIED_EQUIVALENT
        .iter()
        .any(|(c, u, _)| *c == class && *u == unit)
}

/// One mutation class's tally.
#[derive(Debug, Default, Clone)]
struct Tally {
    /// Whether the class's rewrite changes behaviour (the ground-truth label).
    changes: bool,
    /// Pairs where either side did not lower.
    declined: usize,
    /// Pairs the checker was asked about.
    asked: usize,
    /// Verdict `Different`.
    different: usize,
    /// Verdict `Equivalent`.
    equivalent: usize,
    /// Verdict `Unknown`, by reason.
    unknown: BTreeMap<String, usize>,
    /// Units whose verdict contradicts the catalogue's label, kept so the
    /// report can name them. A behaviour-changing class that came back
    /// `Equivalent` is either an unsoundness in this checker or an instance the
    /// class's own caveat covers ("no effect if the literal sits on dead
    /// code"), and only reading the function tells the two apart.
    contradictions: Vec<String>,
}

impl Tally {
    fn abstained(&self) -> usize {
        self.unknown.values().sum()
    }

    fn decided(&self) -> usize {
        self.different + self.equivalent
    }
}

/// The reason class of an abstention, without the variable parts, so the
/// breakdown groups.
fn reason_of(reason: &Unknown) -> String {
    match reason {
        Unknown::NoObservableResult => "void result".to_string(),
        Unknown::ContractMismatch(_) => "contract mismatch".to_string(),
        Unknown::NoCompletePath(side) => format!("no complete path ({side})"),
        Unknown::PartialCoverage => "partial coverage".to_string(),
        Unknown::Solver(reason) => format!("solver unknown ({})", reason.as_str()),
        Unknown::NoSolver => "no solver".to_string(),
        Unknown::SolverError(_) => "solver error".to_string(),
        Unknown::WitnessUnconfirmed => "witness unconfirmed".to_string(),
        Unknown::QueryTooLarge(_) => "query too large".to_string(),
    }
}

/// One corpus row: a function, a mutation class, and the two texts.
struct Record {
    class: String,
    changes: bool,
    unit: String,
    name: String,
    original: String,
    mutant: String,
}

/// Read the JSONL corpus.
fn records(path: &Path) -> Vec<Record> {
    let text = std::fs::read_to_string(path).expect("the corpus file is readable");
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).expect("every corpus line is one JSON object");
        let field = |key: &str| {
            value[key]
                .as_str()
                .unwrap_or_else(|| panic!("corpus record has no string `{key}`"))
                .to_string()
        };
        out.push(Record {
            class: field("class"),
            changes: value["changes"].as_bool().expect("`changes` is a bool"),
            unit: field("unit"),
            name: field("name"),
            original: field("original"),
            mutant: field("mutant"),
        });
    }
    out
}

#[test]
fn equivalence_checker_mutation_scorecard() {
    let Some(path) = corpus_path() else {
        crate::testing::missing_fixture("tests/csource_equiv/mutants.jsonl");
        return;
    };
    let bounds = Bounds::default();
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    // What became of the cells someone already verified as equivalent. A
    // `Different` there contradicts that verification; an `Unknown` only means
    // the checker could not decide it today.
    let mut verified_now_different: Vec<String> = Vec::new();
    let mut verified_now_unknown: Vec<String> = Vec::new();

    let all = records(&path);
    let total = all.len();
    for (index, record) in all.into_iter().enumerate() {
        if index % 200 == 0 {
            eprintln!("scorecard: {index}/{total}");
        }
        let Record {
            class,
            changes,
            unit,
            name,
            original,
            mutant,
        } = record;
        let entry = tallies.entry(class.clone()).or_default();
        entry.changes = changes;
        let (Ok(left), Ok(right)) = (
            lower_named_function(&original, &name),
            lower_named_function(&mutant, &name),
        ) else {
            entry.declined += 1;
            continue;
        };
        entry.asked += 1;
        match check_lowered(&left, &right, bounds.clone()).verdict {
            Verdict::Different => {
                entry.different += 1;
                if !changes {
                    entry.contradictions.push(unit.clone());
                }
                if is_verified_equivalent(&class, &unit) {
                    verified_now_different.push(format!("{class} {unit}"));
                }
            }
            Verdict::Equivalent => {
                entry.equivalent += 1;
                if changes {
                    entry.contradictions.push(unit.clone());
                }
            }
            Verdict::Unknown(reason) => {
                if is_verified_equivalent(&class, &unit) {
                    verified_now_unknown.push(format!("{class} {unit} ({})", reason_of(&reason)));
                }
                *entry.unknown.entry(reason_of(&reason)).or_default() += 1;
            }
        }
    }

    report(&bounds, &tallies);

    // The instrument has to have measured something on both halves, or the
    // rates below are ratios over an empty denominator.
    let changing: usize = tallies
        .values()
        .filter(|t| t.changes)
        .map(Tally::decided)
        .sum();
    let preserving: usize = tallies
        .values()
        .filter(|t| !t.changes)
        .map(Tally::decided)
        .sum();
    assert!(
        changing > 0 && preserving > 0,
        "the scorecard decided {changing} changing and {preserving} preserving cells; \
         with either at zero it separates nothing"
    );

    println!("--- cells whose verdict contradicts the catalogue's label ---");
    for (name, tally) in &tallies {
        for unit in &tally.contradictions {
            println!(
                "  {name} ({}) {unit}",
                if tally.changes {
                    "labelled changing, proved equivalent"
                } else {
                    "labelled preserving, FLAGGED"
                }
            );
        }
    }

    // The gate: a semantics-preserving rewrite must not be flagged. Every one
    // that is would be a defect in this checker or a mislabelled class in the
    // catalogue, and either is a finding rather than a tolerance.
    let alarms: Vec<String> = tallies
        .iter()
        .filter(|(_, t)| !t.changes && t.different > 0)
        .map(|(name, t)| format!("{name}: {} of {}", t.different, t.decided()))
        .collect();
    assert!(
        alarms.is_empty(),
        "semantics-preserving classes were flagged as different: {alarms:?}"
    );

    // ...and a mutant proved `Equivalent` against the catalogue's label is a
    // false negative until somebody has read the pair and said otherwise. That
    // is the one verdict this checker must never get wrong, so the gate names
    // the exceptions individually rather than tolerating a percentage of them.
    let proved_equivalent: Vec<(&str, &str)> = tallies
        .iter()
        .filter(|(_, t)| t.changes)
        .flat_map(|(class, t)| {
            t.contradictions
                .iter()
                .map(move |unit| (class.as_str(), unit.as_str()))
        })
        .collect();

    let unverified: Vec<String> = proved_equivalent
        .iter()
        .filter(|(class, unit)| {
            !VERIFIED_EQUIVALENT
                .iter()
                .any(|(c, u, _)| c == class && u == unit)
        })
        .map(|(class, unit)| format!("{class} {unit}"))
        .collect();
    assert!(
        unverified.is_empty(),
        "these were proved equivalent and nobody has verified that they are: \
         {unverified:?}. Read each pair. If it really is equivalent, add it to \
         VERIFIED_EQUIVALENT with the reason; if it is not, this checker is unsound \
         and the verdict is the bug."
    );

    // An allowlist nobody checks decays into a blanket exemption, but the two
    // ways an entry can stop firing are not the same finding.
    //
    // `Different` contradicts the verification outright: either the reasoning
    // recorded next to the entry is wrong, or the checker now disagrees with
    // it. Somebody has to look, so it fails.
    assert!(
        verified_now_different.is_empty(),
        "VERIFIED_EQUIVALENT says these are equivalent and the checker now calls them \
         different: {verified_now_different:?}. One of the two is wrong --- re-read the \
         pair before touching either."
    );

    // `Unknown` is only a loss of precision, and it is legitimately unstable:
    // the solver wall is wall-clock, so a loaded machine can push a decided
    // cell into `solver unknown (wall-timeout)` and back. Failing on that would
    // make this test flaky for a reason that has nothing to do with soundness,
    // so it is reported and not asserted.
    if !verified_now_unknown.is_empty() {
        println!(
            "--- verified-equivalent cells the checker abstained on this run ({}) ---",
            verified_now_unknown.len()
        );
        for cell in &verified_now_unknown {
            println!("  {cell}");
        }
    }

    // The floor stays as a second, weaker net: it catches a checker that has
    // started proving everything equal, a failure mode that would leave
    // specificity at a perfect 100% while making the oracle worthless. It is
    // not a substitute for the per-cell gate above --- a 90% floor passes with
    // a real unsoundness inside it, which is how the one above was nearly lost.
    let changing_caught: usize = tallies
        .values()
        .filter(|t| t.changes)
        .map(|t| t.different)
        .sum();
    let sensitivity = 100.0 * changing_caught as f64 / changing as f64;
    assert!(
        sensitivity >= 90.0,
        "sensitivity over decided cells fell to {sensitivity:.1}% \
         ({changing_caught}/{changing}); every shortfall is listed above and \
         has to be read before this floor is lowered"
    );
}

/// Print the per-class table. Printed rather than asserted: the numbers are the
/// result of the stage, and pinning them in an assertion would turn a corpus
/// regeneration into a test failure.
fn report(bounds: &Bounds, tallies: &BTreeMap<String, Tally>) {
    println!("--- S5 equivalence scorecard over tests/csource_equiv/mutants.jsonl ---");
    println!(
        "bounds: unroll {} block entries, {} steps/path, {} paths/function, \
         solver wall {} ms",
        bounds.max_block_visits, bounds.max_steps, bounds.max_paths, bounds.solver_timeout_ms
    );
    println!(
        "{:<20} {:>4} {:>6} {:>6} {:>6} {:>7} {:>8} {:>9}",
        "class", "lab", "asked", "diff", "equiv", "unknown", "rate", "declined"
    );
    for (name, tally) in tallies {
        let rate = if tally.asked == 0 {
            0.0
        } else {
            100.0 * tally.abstained() as f64 / tally.asked as f64
        };
        println!(
            "{:<20} {:>4} {:>6} {:>6} {:>6} {:>7} {:>6.1}% {:>9}",
            name,
            if tally.changes { "chg" } else { "keep" },
            tally.asked,
            tally.different,
            tally.equivalent,
            tally.abstained(),
            rate,
            tally.declined,
        );
        for (reason, count) in &tally.unknown {
            println!("{:<20}   unknown: {reason} x{count}", "");
        }
    }

    for (label, changes) in [("sensitivity", true), ("specificity", false)] {
        let decided: usize = tallies
            .values()
            .filter(|t| t.changes == changes)
            .map(Tally::decided)
            .sum();
        let correct: usize = tallies
            .values()
            .filter(|t| t.changes == changes)
            .map(|t| if changes { t.different } else { t.equivalent })
            .sum();
        let asked: usize = tallies
            .values()
            .filter(|t| t.changes == changes)
            .map(|t| t.asked)
            .sum();
        println!(
            "{label}: {correct}/{decided} decided cells ({:.1}%), abstained on {} of {asked}",
            if decided == 0 {
                0.0
            } else {
                100.0 * correct as f64 / decided as f64
            },
            asked - decided,
        );
    }
}
