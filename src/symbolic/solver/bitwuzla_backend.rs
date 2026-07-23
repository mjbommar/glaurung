//! Benchmark-only in-process Bitwuzla backend.
//!
//! This module binds the official Bitwuzla 0.9.1 C API directly. It is kept
//! behind `solver-bitwuzla` and is never considered by production backend
//! selection; its sole purpose is the registered neutral cold/warm regime map.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::{Duration, Instant};

use crate::ir::types::{BinOp, CmpOp, UnOp, Width};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{
    Assert, BitwuzlaExecutionClass, IncrementalSolver, Model, SolveResult, SolveUnknownReason,
    Solver, SolverWorkBudgets, WarmAssertionPrefix, WarmDeltaContext, check_timeout,
    check_timeout_ms, solver_work_budgets,
};

const PINNED_API_VERSION: &str = "0.9.1";

// Values extracted from the official Bitwuzla 0.9.1 C enums at build-review
// time. The runtime version gate in `NativeSession::new` rejects any other ABI.
const OPT_PRODUCE_MODELS: c_int = 1;
const OPT_TIME_LIMIT_PER: c_int = 7;
const RESULT_UNKNOWN: c_int = 0;
const RESULT_SAT: c_int = 10;
const RESULT_UNSAT: c_int = 20;
const KIND_DISTINCT: c_int = 5;
const KIND_EQUAL: c_int = 6;
const KIND_ITE: c_int = 12;
const KIND_BV_ADD: c_int = 19;
const KIND_BV_AND: c_int = 20;
const KIND_BV_ASHR: c_int = 21;
const KIND_BV_CONCAT: c_int = 23;
const KIND_BV_MUL: c_int = 26;
const KIND_BV_NEG: c_int = 28;
const KIND_BV_NOT: c_int = 31;
const KIND_BV_OR: c_int = 32;
const KIND_BV_SHL: c_int = 43;
const KIND_BV_SHR: c_int = 44;
const KIND_BV_SLE: c_int = 45;
const KIND_BV_SLT: c_int = 46;
const KIND_BV_SUB: c_int = 51;
const KIND_BV_UDIV: c_int = 53;
const KIND_BV_ULE: c_int = 56;
const KIND_BV_ULT: c_int = 57;
const KIND_BV_XOR: c_int = 62;
const KIND_BV_EXTRACT: c_int = 63;
const KIND_BV_SIGN_EXTEND: c_int = 67;
const KIND_BV_ZERO_EXTEND: c_int = 68;

#[repr(C)]
struct NativeOptions {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeTermManager {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeSolver {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeSort {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeTerm {
    _private: [u8; 0],
}

type RawSort = *mut NativeSort;
type RawTerm = *mut NativeTerm;

#[link(name = "bitwuzla")]
unsafe extern "C" {
    fn bitwuzla_version() -> *const c_char;
    fn bitwuzla_options_new() -> *mut NativeOptions;
    fn bitwuzla_options_delete(options: *mut NativeOptions);
    fn bitwuzla_set_option(options: *mut NativeOptions, option: c_int, value: u64);
    fn bitwuzla_term_manager_new() -> *mut NativeTermManager;
    fn bitwuzla_new(
        term_manager: *mut NativeTermManager,
        options: *const NativeOptions,
    ) -> *mut NativeSolver;
    fn bitwuzla_delete(solver: *mut NativeSolver);
    fn bitwuzla_push(solver: *mut NativeSolver, levels: u64);
    fn bitwuzla_pop(solver: *mut NativeSolver, levels: u64);
    fn bitwuzla_assert(solver: *mut NativeSolver, term: RawTerm);
    fn bitwuzla_check_sat(solver: *mut NativeSolver) -> c_int;
    fn bitwuzla_check_sat_assuming(
        solver: *mut NativeSolver,
        count: u32,
        assumptions: *mut RawTerm,
    ) -> c_int;
    fn bitwuzla_set_termination_callback(
        solver: *mut NativeSolver,
        callback: extern "C" fn(*mut c_void) -> i32,
        state: *mut c_void,
    );
    fn bitwuzla_get_value(solver: *mut NativeSolver, term: RawTerm) -> RawTerm;
    fn bitwuzla_mk_bv_sort(term_manager: *mut NativeTermManager, size: u64) -> RawSort;
    fn bitwuzla_sort_release(sort: RawSort);
    fn bitwuzla_mk_bv_value(
        term_manager: *mut NativeTermManager,
        sort: RawSort,
        value: *const c_char,
        base: u8,
    ) -> RawTerm;
    fn bitwuzla_mk_const(
        term_manager: *mut NativeTermManager,
        sort: RawSort,
        symbol: *const c_char,
    ) -> RawTerm;
    fn bitwuzla_mk_term1(
        term_manager: *mut NativeTermManager,
        kind: c_int,
        argument: RawTerm,
    ) -> RawTerm;
    fn bitwuzla_mk_term2(
        term_manager: *mut NativeTermManager,
        kind: c_int,
        left: RawTerm,
        right: RawTerm,
    ) -> RawTerm;
    fn bitwuzla_mk_term3(
        term_manager: *mut NativeTermManager,
        kind: c_int,
        first: RawTerm,
        second: RawTerm,
        third: RawTerm,
    ) -> RawTerm;
    fn bitwuzla_mk_term1_indexed1(
        term_manager: *mut NativeTermManager,
        kind: c_int,
        argument: RawTerm,
        index: u64,
    ) -> RawTerm;
    fn bitwuzla_mk_term1_indexed2(
        term_manager: *mut NativeTermManager,
        kind: c_int,
        argument: RawTerm,
        first_index: u64,
        second_index: u64,
    ) -> RawTerm;
    fn bitwuzla_term_value_get_str_fmt(term: RawTerm, base: u8) -> *const c_char;
    fn bitwuzla_term_release(term: RawTerm);
}

struct TerminationBudget {
    poll_limit: u64,
    polls: u64,
    wall_cap: Duration,
    deadline: Instant,
    reason: Option<SolveUnknownReason>,
}

impl TerminationBudget {
    fn new(poll_limit: u64, wall_cap: Duration) -> Self {
        Self {
            poll_limit,
            polls: 0,
            wall_cap,
            deadline: Instant::now() + wall_cap,
            reason: None,
        }
    }

    fn reset(&mut self) {
        self.polls = 0;
        self.deadline = Instant::now() + self.wall_cap;
        self.reason = None;
    }
}

extern "C" fn termination_callback(state: *mut c_void) -> i32 {
    // SAFETY: `NativeSession` registers a pointer to its stable boxed
    // `TerminationBudget`, keeps the box alive for the solver lifetime, and
    // deletes the solver before dropping the box.
    let budget = unsafe { &mut *state.cast::<TerminationBudget>() };
    if budget.polls >= budget.poll_limit {
        budget.reason = Some(SolveUnknownReason::ResourceLimit);
        return 1;
    }
    budget.polls += 1;
    if Instant::now() >= budget.deadline {
        budget.reason = Some(SolveUnknownReason::WallTimeout);
        return 1;
    }
    0
}

thread_local! {
    /// Bitwuzla's term manager is the topology-equivalent peer of Z3's reused
    /// per-thread context. Individual cold checks still create fresh solvers;
    /// warm checks retain a solver. Terms and sorts are explicitly released.
    static TERM_MANAGER: *mut NativeTermManager = {
        // SAFETY: Constructor has no preconditions and the process-lifetime
        // manager remains thread-confined by `thread_local!`.
        let manager = unsafe { bitwuzla_term_manager_new() };
        assert!(!manager.is_null(), "Bitwuzla returned a null term manager");
        manager
    };
}

fn with_term_manager<T>(action: impl FnOnce(*mut NativeTermManager) -> T) -> T {
    TERM_MANAGER.with(|manager| action(*manager))
}

struct OwnedSort(RawSort);

impl Drop for OwnedSort {
    fn drop(&mut self) {
        // SAFETY: Every `OwnedSort` wraps one owned reference returned by the
        // active term manager and is released exactly once here.
        unsafe { bitwuzla_sort_release(self.0) };
    }
}

struct OwnedTerm(RawTerm);

impl Drop for OwnedTerm {
    fn drop(&mut self) {
        // SAFETY: Every `OwnedTerm` wraps one owned reference returned by the
        // active term manager and is released exactly once here.
        unsafe { bitwuzla_term_release(self.0) };
    }
}

struct Translator<'a> {
    term_manager: *mut NativeTermManager,
    terms: Vec<OwnedTerm>,
    memo: BTreeMap<ExprId, RawTerm>,
    symbols: &'a mut BTreeMap<(u32, Width), OwnedTerm>,
}

impl<'a> Translator<'a> {
    fn new(
        term_manager: *mut NativeTermManager,
        symbols: &'a mut BTreeMap<(u32, Width), OwnedTerm>,
    ) -> Self {
        Self {
            term_manager,
            terms: Vec::new(),
            memo: BTreeMap::new(),
            symbols,
        }
    }

    fn own_term(&mut self, term: RawTerm, context: &str) -> Result<RawTerm, String> {
        if term.is_null() {
            return Err(format!("Bitwuzla returned a null term while {context}"));
        }
        self.terms.push(OwnedTerm(term));
        Ok(term)
    }

    fn sort(&self, bits: u16) -> Result<OwnedSort, String> {
        if bits == 0 {
            return Err("Bitwuzla cannot create a zero-width bit-vector sort".into());
        }
        // SAFETY: The thread-confined manager is live and `bits` is nonzero.
        let sort = unsafe { bitwuzla_mk_bv_sort(self.term_manager, u64::from(bits)) };
        if sort.is_null() {
            Err(format!("Bitwuzla returned a null {bits}-bit sort"))
        } else {
            Ok(OwnedSort(sort))
        }
    }

    fn value(&mut self, bits: u16, value: u128) -> Result<RawTerm, String> {
        let sort = self.sort(bits)?;
        let value = CString::new(value.to_string())
            .map_err(|_| "decimal bit-vector value contained NUL".to_string())?;
        // SAFETY: Manager/sort are live and the decimal string is NUL-terminated.
        let term = unsafe { bitwuzla_mk_bv_value(self.term_manager, sort.0, value.as_ptr(), 10) };
        self.own_term(term, "creating a bit-vector value")
    }

    fn symbol(&mut self, id: u32, width: Width) -> Result<RawTerm, String> {
        if let Some(term) = self.symbols.get(&(id, width)) {
            return Ok(term.0);
        }
        let sort = self.sort(width.bits())?;
        let name = CString::new(ExprPool::sym_name(id, width))
            .map_err(|_| "symbol name contained NUL".to_string())?;
        // SAFETY: Manager/sort are live and the symbol is NUL-terminated.
        let term = unsafe { bitwuzla_mk_const(self.term_manager, sort.0, name.as_ptr()) };
        if term.is_null() {
            return Err("Bitwuzla returned null while creating a symbolic constant".into());
        }
        self.symbols.insert((id, width), OwnedTerm(term));
        Ok(term)
    }

    fn term1(&mut self, kind: c_int, argument: RawTerm) -> Result<RawTerm, String> {
        // SAFETY: All inputs are live terms owned by this translator.
        let term = unsafe { bitwuzla_mk_term1(self.term_manager, kind, argument) };
        self.own_term(term, "creating a unary term")
    }

    fn term2(&mut self, kind: c_int, left: RawTerm, right: RawTerm) -> Result<RawTerm, String> {
        // SAFETY: All inputs are live terms owned by this translator.
        let term = unsafe { bitwuzla_mk_term2(self.term_manager, kind, left, right) };
        self.own_term(term, "creating a binary term")
    }

    fn term3(
        &mut self,
        kind: c_int,
        first: RawTerm,
        second: RawTerm,
        third: RawTerm,
    ) -> Result<RawTerm, String> {
        // SAFETY: All inputs are live terms owned by this translator.
        let term = unsafe { bitwuzla_mk_term3(self.term_manager, kind, first, second, third) };
        self.own_term(term, "creating a ternary term")
    }

    fn indexed1(&mut self, kind: c_int, argument: RawTerm, index: u64) -> Result<RawTerm, String> {
        // SAFETY: The input is a live term and the index is validated by the
        // typed Glaurung expression node before reaching this adapter.
        let term = unsafe { bitwuzla_mk_term1_indexed1(self.term_manager, kind, argument, index) };
        self.own_term(term, "creating a one-index term")
    }

    fn indexed2(
        &mut self,
        kind: c_int,
        argument: RawTerm,
        first: u64,
        second: u64,
    ) -> Result<RawTerm, String> {
        // SAFETY: The input is a live term and indices are validated by the
        // typed Glaurung expression node before reaching this adapter.
        let term =
            unsafe { bitwuzla_mk_term1_indexed2(self.term_manager, kind, argument, first, second) };
        self.own_term(term, "creating a two-index term")
    }

    fn coerce(&mut self, term: RawTerm, from: u16, to: u16) -> Result<RawTerm, String> {
        if from == to {
            Ok(term)
        } else if from < to {
            self.indexed1(KIND_BV_ZERO_EXTEND, term, u64::from(to - from))
        } else {
            self.indexed2(KIND_BV_EXTRACT, term, u64::from(to - 1), 0)
        }
    }

    fn expression(&mut self, pool: &ExprPool, id: ExprId) -> Result<RawTerm, String> {
        if let Some(&term) = self.memo.get(&id) {
            return Ok(term);
        }
        let term = match *pool.get(id) {
            Expr::Const { value, width } => self.value(width.bits(), value)?,
            Expr::Sym { id, width } => self.symbol(id, width)?,
            Expr::Bin { op, a, b, width } => {
                let bits = width.bits();
                let left = self.expression(pool, a)?;
                let left = self.coerce(left, pool.width_of(a).bits(), bits)?;
                let right = self.expression(pool, b)?;
                let right = self.coerce(right, pool.width_of(b).bits(), bits)?;
                let kind = match op {
                    BinOp::Add => KIND_BV_ADD,
                    BinOp::Sub => KIND_BV_SUB,
                    BinOp::Mul => KIND_BV_MUL,
                    BinOp::Div => KIND_BV_UDIV,
                    BinOp::And => KIND_BV_AND,
                    BinOp::Or => KIND_BV_OR,
                    BinOp::Xor => KIND_BV_XOR,
                    BinOp::Shl => KIND_BV_SHL,
                    BinOp::Shr => KIND_BV_SHR,
                    BinOp::Sar => KIND_BV_ASHR,
                };
                self.term2(kind, left, right)?
            }
            Expr::Un { op, a, .. } => {
                let argument = self.expression(pool, a)?;
                self.term1(
                    match op {
                        UnOp::Not => KIND_BV_NOT,
                        UnOp::Neg => KIND_BV_NEG,
                    },
                    argument,
                )?
            }
            Expr::Cmp { op, a, b, width } => {
                let bits = width.bits();
                let left = self.expression(pool, a)?;
                let left = self.coerce(left, pool.width_of(a).bits(), bits)?;
                let right = self.expression(pool, b)?;
                let right = self.coerce(right, pool.width_of(b).bits(), bits)?;
                let condition = self.term2(
                    match op {
                        CmpOp::Eq => KIND_EQUAL,
                        CmpOp::Ne => KIND_DISTINCT,
                        CmpOp::Ult => KIND_BV_ULT,
                        CmpOp::Ule => KIND_BV_ULE,
                        CmpOp::Slt => KIND_BV_SLT,
                        CmpOp::Sle => KIND_BV_SLE,
                    },
                    left,
                    right,
                )?;
                let one = self.value(1, 1)?;
                let zero = self.value(1, 0)?;
                self.term3(KIND_ITE, condition, one, zero)?
            }
            Expr::ZExt { a, from, to } => {
                let argument = self.expression(pool, a)?;
                let argument = self.coerce(argument, pool.width_of(a).bits(), from.bits())?;
                self.indexed1(
                    KIND_BV_ZERO_EXTEND,
                    argument,
                    u64::from(to.bits() - from.bits()),
                )?
            }
            Expr::SExt { a, from, to } => {
                let argument = self.expression(pool, a)?;
                let argument = self.coerce(argument, pool.width_of(a).bits(), from.bits())?;
                self.indexed1(
                    KIND_BV_SIGN_EXTEND,
                    argument,
                    u64::from(to.bits() - from.bits()),
                )?
            }
            Expr::Trunc { a, to } => {
                let argument = self.expression(pool, a)?;
                let argument = self.coerce(argument, pool.width_of(a).bits(), to.bits())?;
                self.indexed2(KIND_BV_EXTRACT, argument, u64::from(to.bits() - 1), 0)?
            }
            Expr::Extract { a, hi, lo } => {
                let argument = self.expression(pool, a)?;
                let argument = self.coerce(argument, pool.width_of(a).bits(), hi)?;
                self.indexed2(KIND_BV_EXTRACT, argument, u64::from(hi - 1), u64::from(lo))?
            }
            Expr::Concat { hi, lo, hi_w, lo_w } => {
                let high = self.expression(pool, hi)?;
                let high = self.coerce(high, pool.width_of(hi).bits(), hi_w.bits())?;
                let low = self.expression(pool, lo)?;
                let low = self.coerce(low, pool.width_of(lo).bits(), lo_w.bits())?;
                self.term2(KIND_BV_CONCAT, high, low)?
            }
            Expr::Ite { c, t, e, width } => {
                let condition = self.expression(pool, c)?;
                let one = self.value(1, 1)?;
                let condition = self.term2(KIND_EQUAL, condition, one)?;
                let bits = width.bits();
                let then_term = self.expression(pool, t)?;
                let then_term = self.coerce(then_term, pool.width_of(t).bits(), bits)?;
                let else_term = self.expression(pool, e)?;
                let else_term = self.coerce(else_term, pool.width_of(e).bits(), bits)?;
                self.term3(KIND_ITE, condition, then_term, else_term)?
            }
        };
        self.memo.insert(id, term);
        Ok(term)
    }

    fn assertion(
        &mut self,
        pool: &ExprPool,
        (expression, expected): Assert,
    ) -> Result<RawTerm, String> {
        let value = self.expression(pool, expression)?;
        let width = pool.width_of(expression).bits();
        let zero = self.value(width, 0)?;
        self.term2(
            if expected { KIND_DISTINCT } else { KIND_EQUAL },
            value,
            zero,
        )
    }
}

struct NativeSession {
    options: *mut NativeOptions,
    solver: *mut NativeSolver,
    termination: Option<Box<TerminationBudget>>,
    symbol_terms: BTreeMap<(u32, Width), OwnedTerm>,
}

impl NativeSession {
    fn new(term_manager: *mut NativeTermManager) -> Result<Self, String> {
        Self::new_with_work_budgets(term_manager, solver_work_budgets())
    }

    fn new_with_work_budgets(
        term_manager: *mut NativeTermManager,
        work_budgets: SolverWorkBudgets,
    ) -> Result<Self, String> {
        let version = BitwuzlaSolver::api_version();
        if version != PINNED_API_VERSION {
            return Err(format!(
                "Bitwuzla C API version {version}; required {PINNED_API_VERSION}"
            ));
        }
        // SAFETY: Constructor has no preconditions.
        let options = unsafe { bitwuzla_options_new() };
        if options.is_null() {
            return Err("Bitwuzla returned null options".into());
        }
        // SAFETY: Options are live and both enum values are pinned to 0.9.1.
        unsafe {
            bitwuzla_set_option(options, OPT_PRODUCE_MODELS, 1);
            if work_budgets.bitwuzla_termination_polls.is_none() {
                bitwuzla_set_option(options, OPT_TIME_LIMIT_PER, check_timeout_ms());
            }
        }
        // SAFETY: The thread-confined term manager and options are live.
        let solver = unsafe { bitwuzla_new(term_manager, options) };
        if solver.is_null() {
            // SAFETY: Options were allocated above and have not been freed.
            unsafe { bitwuzla_options_delete(options) };
            return Err("Bitwuzla returned a null solver".into());
        }
        let mut termination = work_budgets
            .bitwuzla_termination_polls
            .map(|limit| Box::new(TerminationBudget::new(limit, check_timeout())));
        if let Some(budget) = termination.as_deref_mut() {
            // SAFETY: The solver is live. The callback state points into a
            // stable box retained by this session until after solver deletion.
            unsafe {
                bitwuzla_set_termination_callback(
                    solver,
                    termination_callback,
                    (budget as *mut TerminationBudget).cast(),
                );
            }
        }
        Ok(Self {
            options,
            solver,
            termination,
            symbol_terms: BTreeMap::new(),
        })
    }

    fn prepare_check(&mut self) {
        if let Some(budget) = self.termination.as_deref_mut() {
            budget.reset();
        }
    }

    fn result(&mut self, result: c_int, symbols: &BTreeMap<u32, Width>) -> SolveResult {
        match result {
            RESULT_UNSAT => SolveResult::Unsat,
            RESULT_UNKNOWN => SolveResult::Unknown(
                self.termination
                    .as_ref()
                    .and_then(|budget| budget.reason)
                    .unwrap_or(SolveUnknownReason::Other),
            ),
            RESULT_SAT => match self.model(symbols) {
                Ok(model) => SolveResult::Sat(model),
                Err(error) => SolveResult::Error(error),
            },
            other => SolveResult::Error(format!("unexpected Bitwuzla result code {other}")),
        }
    }

    fn model(&mut self, symbols: &BTreeMap<u32, Width>) -> Result<Model, String> {
        let mut values = BTreeMap::new();
        for (&id, &width) in symbols {
            let symbol = self
                .symbol_terms
                .get(&(id, width))
                .ok_or_else(|| format!("Bitwuzla model symbol sym{id} was not translated"))?
                .0;
            // SAFETY: The solver's immediately preceding result was SAT and
            // `symbol` belongs to its term manager.
            let value = unsafe { bitwuzla_get_value(self.solver, symbol) };
            if value.is_null() {
                return Err(format!("Bitwuzla returned null model value for sym{id}"));
            }
            let value = OwnedTerm(value);
            // SAFETY: `value` is a live bit-vector value term. The returned
            // string remains valid until the next formatted value read.
            let rendered = unsafe { bitwuzla_term_value_get_str_fmt(value.0, 16) };
            if rendered.is_null() {
                return Err(format!("Bitwuzla returned null model text for sym{id}"));
            }
            // SAFETY: The non-null pointer is documented as NUL-terminated.
            let rendered = unsafe { CStr::from_ptr(rendered) }
                .to_str()
                .map_err(|_| format!("Bitwuzla model text for sym{id} is not UTF-8"))?;
            let digits = rendered.strip_prefix("#x").unwrap_or(rendered);
            let value = u128::from_str_radix(digits, 16).map_err(|error| {
                format!("invalid Bitwuzla hexadecimal model value for sym{id}: {error}")
            })?;
            values.insert(id, value);
        }
        Ok(Model { values })
    }
}

impl Drop for NativeSession {
    fn drop(&mut self) {
        // SAFETY: The solver was created from these live options/term manager;
        // the official examples require deleting the solver before options.
        unsafe {
            bitwuzla_delete(self.solver);
            bitwuzla_options_delete(self.options);
        }
    }
}

/// Official in-process Bitwuzla benchmark adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct BitwuzlaSolver;

impl BitwuzlaSolver {
    pub fn new() -> Self {
        Self
    }

    /// Report the linked C API version rather than trusting build metadata.
    pub fn api_version() -> &'static str {
        // SAFETY: Bitwuzla documents `bitwuzla_version()` as returning a
        // process-lifetime NUL-terminated string. The null/UTF-8 checks fail
        // closed because the measurement protocol requires an exact identity.
        let pointer = unsafe { bitwuzla_version() };
        assert!(
            !pointer.is_null(),
            "Bitwuzla returned a null version string"
        );
        // SAFETY: The non-null pointer has the lifetime and termination
        // contract stated above.
        unsafe { CStr::from_ptr(pointer) }
            .to_str()
            .expect("Bitwuzla version string must be UTF-8")
    }
}

impl Solver for BitwuzlaSolver {
    fn check(&mut self, pool: &ExprPool, assertions: &[Assert]) -> SolveResult {
        with_term_manager(|term_manager| {
            let mut session = match NativeSession::new(term_manager) {
                Ok(session) => session,
                Err(error) => return SolveResult::Error(error),
            };
            let mut translator = Translator::new(term_manager, &mut session.symbol_terms);
            for &assertion in assertions {
                let term = match translator.assertion(pool, assertion) {
                    Ok(term) => term,
                    Err(error) => return SolveResult::Error(error),
                };
                // SAFETY: Solver and Boolean assertion term are live.
                unsafe { bitwuzla_assert(session.solver, term) };
            }
            let mut symbols = BTreeMap::new();
            for &(expression, _) in assertions {
                pool.collect_syms(expression, &mut symbols);
            }
            drop(translator);
            session.prepare_check();
            // SAFETY: Solver is live and fully configured.
            let result = unsafe { bitwuzla_check_sat(session.solver) };
            session.result(result, &symbols)
        })
    }
}

/// Retained Bitwuzla session with the same explicit scope contract as Z3 and
/// Axeyum. It is private to fair-shadow lineage ownership.
pub(crate) struct IncrementalBitwuzlaSolver {
    term_manager: *mut NativeTermManager,
    session: NativeSession,
    symbol_scopes: Vec<BTreeMap<u32, Width>>,
}

impl IncrementalBitwuzlaSolver {
    pub(crate) fn new() -> Result<Self, String> {
        with_term_manager(|term_manager| {
            Ok(Self {
                term_manager,
                session: NativeSession::new(term_manager)?,
                symbol_scopes: vec![BTreeMap::new()],
            })
        })
    }

    fn active_symbols(&self) -> BTreeMap<u32, Width> {
        let mut symbols = BTreeMap::new();
        for scope in &self.symbol_scopes {
            symbols.extend(scope.iter().map(|(&id, &width)| (id, width)));
        }
        symbols
    }
}

impl IncrementalSolver for IncrementalBitwuzlaSolver {
    fn assert(&mut self, pool: &ExprPool, assertion: Assert) -> Result<(), String> {
        let mut translator = Translator::new(self.term_manager, &mut self.session.symbol_terms);
        let term = translator.assertion(pool, assertion)?;
        // SAFETY: Solver and Boolean assertion term are live.
        unsafe { bitwuzla_assert(self.session.solver, term) };
        drop(translator);
        pool.collect_syms(
            assertion.0,
            self.symbol_scopes.last_mut().expect("base scope exists"),
        );
        Ok(())
    }

    fn push(&mut self) -> Result<(), String> {
        // SAFETY: Solver is live and supports incremental scopes.
        unsafe { bitwuzla_push(self.session.solver, 1) };
        self.symbol_scopes.push(BTreeMap::new());
        Ok(())
    }

    fn pop(&mut self) -> bool {
        if self.symbol_scopes.len() == 1 {
            return false;
        }
        // SAFETY: A non-base scope exists.
        unsafe { bitwuzla_pop(self.session.solver, 1) };
        self.symbol_scopes.pop();
        true
    }

    fn scope_depth(&self) -> usize {
        self.symbol_scopes.len() - 1
    }

    fn check(&mut self) -> SolveResult {
        if let Some(budget) = self.session.termination.as_deref_mut() {
            budget.reset();
        }
        // SAFETY: Solver is live and fully configured.
        let result = unsafe { bitwuzla_check_sat(self.session.solver) };
        self.session.result(result, &self.active_symbols())
    }

    fn check_assuming(&mut self, pool: &ExprPool, assumptions: &[Assert]) -> SolveResult {
        let mut symbols = self.active_symbols();
        let mut translator = Translator::new(self.term_manager, &mut self.session.symbol_terms);
        let mut terms = Vec::with_capacity(assumptions.len());
        for &assumption in assumptions {
            let term = match translator.assertion(pool, assumption) {
                Ok(term) => term,
                Err(error) => return SolveResult::Error(error),
            };
            terms.push(term);
            pool.collect_syms(assumption.0, &mut symbols);
        }
        let count = match u32::try_from(terms.len()) {
            Ok(count) => count,
            Err(_) => return SolveResult::Error("too many Bitwuzla assumptions".into()),
        };
        if let Some(budget) = self.session.termination.as_deref_mut() {
            budget.reset();
        }
        // SAFETY: Solver and all assumption terms remain live for this call.
        let result = unsafe {
            bitwuzla_check_sat_assuming(
                self.session.solver,
                count,
                if terms.is_empty() {
                    ptr::null_mut()
                } else {
                    terms.as_mut_ptr()
                },
            )
        };
        drop(translator);
        self.session.result(result, &symbols)
    }
}

struct DirectBitwuzlaPath {
    solver: IncrementalBitwuzlaSolver,
    active_assertions: usize,
    active_prefix: WarmAssertionPrefix,
}

#[derive(Clone, Copy)]
struct DirectBitwuzlaCheckInput<'a> {
    persistent: &'a [Assert],
    persistent_prefix: &'a WarmAssertionPrefix,
    requested_retain: usize,
    temporary: &'a [Assert],
}

#[derive(Default)]
struct DirectDeltaLineageBitwuzlaSolver {
    paths: BTreeMap<u64, DirectBitwuzlaPath>,
}

impl DirectDeltaLineageBitwuzlaSolver {
    fn check_path(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        input: DirectBitwuzlaCheckInput<'_>,
    ) -> (SolveResult, bool, bool) {
        if input.persistent_prefix.depth() != input.persistent.len()
            || input.requested_retain > input.persistent.len()
        {
            self.paths.remove(&path_id);
            return (
                SolveResult::Error(format!(
                    "Bitwuzla direct-delta source depth {}, retain {}, persistent {}",
                    input.persistent_prefix.depth(),
                    input.requested_retain,
                    input.persistent.len()
                )),
                false,
                false,
            );
        }

        let created = !self.paths.contains_key(&path_id);
        if created {
            let solver = match IncrementalBitwuzlaSolver::new() {
                Ok(solver) => solver,
                Err(error) => return (SolveResult::Error(error), false, false),
            };
            self.paths.insert(
                path_id,
                DirectBitwuzlaPath {
                    solver,
                    active_assertions: 0,
                    active_prefix: WarmAssertionPrefix::default(),
                },
            );
        }
        let retain = if created {
            0
        } else {
            self.paths
                .get(&path_id)
                .expect("Bitwuzla path exists while deriving source LCP")
                .active_prefix
                .common_depth(input.persistent_prefix)
        };
        let result = self.transition_and_check(path_id, pool, input, retain);
        let synchronized = !matches!(result, SolveResult::Error(_));
        if !synchronized {
            self.paths.remove(&path_id);
        }
        (result, synchronized, created)
    }

    fn transition_and_check(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        input: DirectBitwuzlaCheckInput<'_>,
        retain: usize,
    ) -> SolveResult {
        let path = self
            .paths
            .get_mut(&path_id)
            .expect("Bitwuzla path was materialized before transition");
        if retain > path.active_assertions || retain > input.persistent.len() {
            return SolveResult::Error(format!(
                "Bitwuzla direct-delta prefix {retain} exceeds active {} or persistent {}",
                path.active_assertions,
                input.persistent.len()
            ));
        }
        while path.active_assertions > retain {
            if !path.solver.pop() {
                return SolveResult::Error(
                    "Bitwuzla direct-delta scope underflow; session reset".into(),
                );
            }
            path.active_assertions -= 1;
        }
        for &assertion in &input.persistent[retain..] {
            if let Err(error) = path.solver.push() {
                return SolveResult::Error(error);
            }
            if let Err(error) = path.solver.assert(pool, assertion) {
                return SolveResult::Error(error);
            }
            path.active_assertions += 1;
        }
        path.active_prefix = input.persistent_prefix.clone();
        if input.temporary.is_empty() {
            path.solver.check()
        } else {
            path.solver.check_assuming(pool, input.temporary)
        }
    }

    fn close_path(&mut self, path_id: u64) -> bool {
        self.paths.remove(&path_id).is_some()
    }
}

thread_local! {
    static DIRECT_DELTA_SOLVERS: RefCell<DirectDeltaLineageBitwuzlaSolver> =
        RefCell::new(DirectDeltaLineageBitwuzlaSolver::default());
    static SERIAL_OWNER_LEASES: RefCell<BTreeMap<u64, u64>> = const { RefCell::new(BTreeMap::new()) };
}

/// Run the fixed direct-lineage Bitwuzla cell used only by neutral fair-shadow
/// diagnostics.
pub(crate) fn check_warm_thread_local(
    pool: &ExprPool,
    assertions: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
) -> (SolveResult, BitwuzlaExecutionClass) {
    let (Some(path_id), Some(delta)) = (path_id, delta) else {
        return (
            SolveResult::Error("missing Bitwuzla fair-shadow lineage delta".into()),
            BitwuzlaExecutionClass::FallbackMissingDelta,
        );
    };
    if delta.persistent_assertions > assertions.len() {
        DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
        return (
            SolveResult::Error(format!(
                "invalid Bitwuzla direct delta: persistent {}, total {}",
                delta.persistent_assertions,
                assertions.len()
            )),
            BitwuzlaExecutionClass::InvalidDirectDelta,
        );
    }
    let (persistent, temporary) = assertions.split_at(delta.persistent_assertions);
    let (result, synchronized, created) = DIRECT_DELTA_SOLVERS.with(|lineage| {
        lineage.borrow_mut().check_path(
            path_id,
            pool,
            DirectBitwuzlaCheckInput {
                persistent,
                persistent_prefix: &delta.persistent_prefix,
                requested_retain: delta.retain_assertions,
                temporary,
            },
        )
    });
    let execution = if !synchronized {
        BitwuzlaExecutionClass::InvalidDirectDelta
    } else if created {
        BitwuzlaExecutionClass::WarmCreated
    } else {
        BitwuzlaExecutionClass::WarmRetained
    };
    (result, execution)
}

pub(crate) fn share_serial_warm_owner_with_children(path_id: u64, children: u64) {
    debug_assert!(children > 0);
    SERIAL_OWNER_LEASES.with(|leases| {
        let mut leases = leases.borrow_mut();
        let references = leases.entry(path_id).or_insert(1);
        *references = references.saturating_add(children);
    });
}

pub(crate) fn close_warm_path(path_id: u64) {
    let close = SERIAL_OWNER_LEASES.with(|leases| {
        let mut leases = leases.borrow_mut();
        let Some(references) = leases.get_mut(&path_id) else {
            return true;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            leases.remove(&path_id);
            true
        } else {
            false
        }
    });
    if close {
        DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, CmpOp, UnOp, Width};
    use crate::symbolic::expr::{Expr, ExprPool};
    use crate::symbolic::solver::{IncrementalSolver, SolveResult, Solver, WarmAssertionPrefix};

    #[test]
    fn termination_budget_stops_on_its_named_poll_limit_and_resets() {
        let mut budget = TerminationBudget::new(1, Duration::from_secs(60));

        assert_eq!(
            termination_callback((&mut budget as *mut TerminationBudget).cast()),
            0
        );
        assert_eq!(
            termination_callback((&mut budget as *mut TerminationBudget).cast()),
            1
        );
        assert_eq!(budget.reason, Some(SolveUnknownReason::ResourceLimit));

        budget.reset();
        assert_eq!(
            termination_callback((&mut budget as *mut TerminationBudget).cast()),
            0
        );
        assert_eq!(budget.reason, None);
    }

    #[test]
    fn native_session_classifies_callback_termination_as_resource_limit() {
        with_term_manager(|term_manager| {
            let mut session = NativeSession::new_with_work_budgets(
                term_manager,
                SolverWorkBudgets {
                    bitwuzla_termination_polls: Some(0),
                    ..SolverWorkBudgets::default()
                },
            )
            .expect("Bitwuzla session");
            session.prepare_check();
            // SAFETY: The session is live and fully configured. A zero limit
            // is injected only here so the first native poll deterministically
            // exercises the callback classification path.
            let result = unsafe { bitwuzla_check_sat(session.solver) };

            assert_eq!(
                session.result(result, &BTreeMap::new()),
                SolveResult::Unknown(SolveUnknownReason::ResourceLimit)
            );
        });
    }

    #[test]
    fn bitwuzla_adapter_reports_its_pinned_api_version() {
        assert_eq!(BitwuzlaSolver::api_version(), "0.9.1");
    }

    fn equality(pool: &mut ExprPool, left: ExprId, right: ExprId, width: Width) -> ExprId {
        pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: left,
            b: right,
            width,
        })
    }

    fn assert_constant_expression(pool: &mut ExprPool, expression: ExprId, expected: u128) {
        let width = pool.width_of(expression);
        let expected = pool.constant(width, expected);
        let equals = equality(pool, expression, expected, width);
        assert!(matches!(
            BitwuzlaSolver::new().check(pool, &[(equals, true)]),
            SolveResult::Sat(_)
        ));
    }

    #[test]
    fn bitwuzla_cold_lifts_full_width_models() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W128);
        let expected_value = (1_u128 << 127) | 0x0123_4567_89ab_cdef;
        let expected = pool.constant(Width::W128, expected_value);
        let equals = equality(&mut pool, x, expected, Width::W128);

        match BitwuzlaSolver::new().check(&pool, &[(equals, true)]) {
            SolveResult::Sat(model) => {
                assert_eq!(model.values.get(&0), Some(&expected_value));
            }
            other => panic!("expected SAT with a model, got {other:?}"),
        }
    }

    #[test]
    fn bitwuzla_translates_the_complete_glaurung_qfbv_surface() {
        let mut pool = ExprPool::new();
        let a8 = pool.constant(Width::W8, 0b1001_0110);
        let b8 = pool.constant(Width::W8, 3);
        for (op, expected) in [
            (BinOp::Add, 0x99),
            (BinOp::Sub, 0x93),
            (BinOp::Mul, 0xc2),
            (BinOp::Div, 0x32),
            (BinOp::And, 0x02),
            (BinOp::Or, 0x97),
            (BinOp::Xor, 0x95),
            (BinOp::Shl, 0xb0),
            (BinOp::Shr, 0x12),
            (BinOp::Sar, 0xf2),
        ] {
            let expression = pool.intern(Expr::Bin {
                op,
                a: a8,
                b: b8,
                width: Width::W8,
            });
            assert_constant_expression(&mut pool, expression, expected);
        }

        for (op, expected) in [(UnOp::Not, 0x69), (UnOp::Neg, 0x6a)] {
            let expression = pool.intern(Expr::Un {
                op,
                a: a8,
                width: Width::W8,
            });
            assert_constant_expression(&mut pool, expression, expected);
        }

        let negative = pool.constant(Width::W8, 0xff);
        let positive = pool.constant(Width::W8, 1);
        for (op, expected) in [
            (CmpOp::Eq, 0),
            (CmpOp::Ne, 1),
            (CmpOp::Ult, 0),
            (CmpOp::Ule, 0),
            (CmpOp::Slt, 1),
            (CmpOp::Sle, 1),
        ] {
            let expression = pool.intern(Expr::Cmp {
                op,
                a: negative,
                b: positive,
                width: Width::W8,
            });
            assert_constant_expression(&mut pool, expression, expected);
        }

        let zext = pool.intern(Expr::ZExt {
            a: negative,
            from: Width::W8,
            to: Width::W16,
        });
        assert_constant_expression(&mut pool, zext, 0x00ff);
        let sext = pool.intern(Expr::SExt {
            a: negative,
            from: Width::W8,
            to: Width::W16,
        });
        assert_constant_expression(&mut pool, sext, 0xffff);
        let trunc = pool.intern(Expr::Trunc {
            a: sext,
            to: Width::W8,
        });
        assert_constant_expression(&mut pool, trunc, 0xff);
        let extract = pool.intern(Expr::Extract {
            a: a8,
            hi: 7,
            lo: 3,
        });
        assert_constant_expression(&mut pool, extract, 0x12);
        let concat = pool.intern(Expr::Concat {
            hi: a8,
            lo: b8,
            hi_w: Width::W8,
            lo_w: Width::W8,
        });
        assert_constant_expression(&mut pool, concat, 0x9603);
        let one = pool.constant(Width::W1, 1);
        let ite = pool.intern(Expr::Ite {
            c: one,
            t: a8,
            e: b8,
            width: Width::W8,
        });
        assert_constant_expression(&mut pool, ite, 0x96);
    }

    #[test]
    fn bitwuzla_incremental_scopes_and_assumptions_restore_state() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W32);
        let zero = pool.constant(Width::W32, 0);
        let one = pool.constant(Width::W32, 1);
        let eq_zero = equality(&mut pool, x, zero, Width::W32);
        let eq_one = equality(&mut pool, x, one, Width::W32);

        let mut solver = IncrementalBitwuzlaSolver::new().expect("Bitwuzla session");
        solver.push().expect("push");
        solver.assert(&pool, (eq_zero, true)).expect("assert");
        assert_eq!(solver.scope_depth(), 1);
        match solver.check() {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&0)),
            other => panic!("expected SAT, got {other:?}"),
        }

        assert_eq!(
            solver.check_assuming(&pool, &[(eq_one, true)]),
            SolveResult::Unsat
        );
        assert!(matches!(solver.check(), SolveResult::Sat(_)));
        solver.push().expect("nested push");
        solver.assert(&pool, (eq_one, true)).expect("nested assert");
        assert_eq!(solver.check(), SolveResult::Unsat);
        assert!(solver.pop());
        assert!(matches!(solver.check(), SolveResult::Sat(_)));
        assert!(solver.pop());
        assert!(!solver.pop());
    }

    #[test]
    fn bitwuzla_direct_lineage_uses_source_ancestry_and_drops_assumptions() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let ten = root.constant(Width::W32, 10);
        let below_ten = root.intern(Expr::Cmp {
            op: CmpOp::Ult,
            a: x,
            b: ten,
            width: Width::W32,
        });
        let mut left = root.clone();
        let five = left.constant(Width::W32, 5);
        let x_is_five = equality(&mut left, x, five, Width::W32);
        let mut right = root.clone();
        let seven = right.constant(Width::W32, 7);
        let x_is_seven = equality(&mut right, x, seven, Width::W32);
        let five_right = right.constant(Width::W32, 5);
        let x_is_five_right = equality(&mut right, x, five_right, Width::W32);

        let mut base = WarmAssertionPrefix::default();
        base.push();
        let mut left_prefix = base.clone();
        left_prefix.push();
        let mut right_prefix = base.clone();
        right_prefix.push();
        let mut lineage = DirectDeltaLineageBitwuzlaSolver::default();

        match lineage.check_path(
            7,
            &left,
            DirectBitwuzlaCheckInput {
                persistent: &[(below_ten, true), (x_is_five, true)],
                persistent_prefix: &left_prefix,
                requested_retain: 0,
                temporary: &[],
            },
        ) {
            (SolveResult::Sat(model), true, true) => {
                assert_eq!(model.values.get(&0), Some(&5));
            }
            other => panic!("expected new left session, got {other:?}"),
        }
        match lineage.check_path(
            7,
            &right,
            DirectBitwuzlaCheckInput {
                persistent: &[(below_ten, true), (x_is_seven, true)],
                persistent_prefix: &right_prefix,
                requested_retain: 2,
                temporary: &[(x_is_five_right, true)],
            },
        ) {
            (SolveResult::Unsat, true, false) => {}
            other => panic!("expected retained right session with temporary UNSAT, got {other:?}"),
        }
        match lineage.check_path(
            7,
            &right,
            DirectBitwuzlaCheckInput {
                persistent: &[(below_ten, true), (x_is_seven, true)],
                persistent_prefix: &right_prefix,
                requested_retain: 2,
                temporary: &[],
            },
        ) {
            (SolveResult::Sat(model), true, false) => {
                assert_eq!(model.values.get(&0), Some(&7));
            }
            other => panic!("temporary assumption leaked or retention failed: {other:?}"),
        }
        assert_eq!(left_prefix.common_depth(&right_prefix), 1);
        assert!(lineage.close_path(7));
        assert!(!lineage.close_path(7));
    }
}
