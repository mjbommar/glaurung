//! Opt-in timing and parse-count evidence for the decompiler pipeline.

use std::cell::Cell;
use std::time::Instant;

use serde::Serialize;

const PREFIX: &str = "[glaurung-pipeline-profile] ";
const SCHEMA: &str = "glaurung-pipeline-profile-v1";

thread_local! {
    static ACTIVE_RUNS: Cell<u32> = const { Cell::new(0) };
    static OBJECT_PARSE_TOTAL: Cell<u64> = const { Cell::new(0) };
}

#[derive(Debug, Serialize)]
struct StageProfileEvent<'a> {
    schema: &'static str,
    event: &'static str,
    function: &'a str,
    entry_va: String,
    stage: &'a str,
    duration_ns: u64,
}

#[derive(Debug, Serialize)]
struct RunProfileEvent<'a> {
    schema: &'static str,
    event: &'static str,
    entry_point: &'a str,
    duration_ns: u64,
    object_parse_count: u64,
}

/// Times named stages for one function when profiling is enabled.
pub(crate) struct FunctionProfiler {
    enabled: bool,
    function: String,
    entry_va: u64,
}

impl FunctionProfiler {
    /// Construct a profiler using the process-level opt-in environment variable.
    pub(crate) fn from_env(function: impl Into<String>, entry_va: u64) -> Self {
        Self {
            enabled: std::env::var_os("GLAURUNG_PIPELINE_PROFILE").is_some(),
            function: function.into(),
            entry_va,
        }
    }

    /// Execute one stage and emit its elapsed wall time without changing output.
    pub(crate) fn measure<T>(&mut self, stage: &str, operation: impl FnOnce() -> T) -> T {
        if !self.enabled {
            return operation();
        }
        let started = Instant::now();
        let output = operation();
        let event = StageProfileEvent {
            schema: SCHEMA,
            event: "stage",
            function: &self.function,
            entry_va: format!("{:#x}", self.entry_va),
            stage,
            duration_ns: saturating_nanos(started.elapsed()),
        };
        emit(&event);
        output
    }
}

/// Profiles one public decompilation entry point and owns its parse counter.
pub(crate) struct RunProfiler {
    enabled: bool,
    entry_point: &'static str,
    started: Instant,
    parse_total_at_start: u64,
}

impl RunProfiler {
    /// Begin a run if profiling was explicitly enabled.
    pub(crate) fn from_env(entry_point: &'static str) -> Self {
        let enabled = std::env::var_os("GLAURUNG_PIPELINE_PROFILE").is_some();
        let parse_total_at_start = OBJECT_PARSE_TOTAL.with(Cell::get);
        if enabled {
            ACTIVE_RUNS.with(|active| active.set(active.get().saturating_add(1)));
        }
        Self {
            enabled,
            entry_point,
            started: Instant::now(),
            parse_total_at_start,
        }
    }

    fn object_parse_count(&self) -> u64 {
        OBJECT_PARSE_TOTAL
            .with(Cell::get)
            .saturating_sub(self.parse_total_at_start)
    }
}

impl Drop for RunProfiler {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        ACTIVE_RUNS.with(|active| active.set(active.get().saturating_sub(1)));
        let object_parse_count = self.object_parse_count();
        let event = RunProfileEvent {
            schema: SCHEMA,
            event: "run",
            entry_point: self.entry_point,
            duration_ns: saturating_nanos(self.started.elapsed()),
            object_parse_count,
        };
        emit(&event);
    }
}

/// The single production adapter for parsing an object image.
pub(crate) fn parse_object(data: &[u8]) -> object::read::Result<object::read::File<'_>> {
    ACTIVE_RUNS.with(|active| {
        if active.get() != 0 {
            OBJECT_PARSE_TOTAL.with(|count| count.set(count.get().saturating_add(1)));
        }
    });
    object::read::File::parse(data)
}

fn saturating_nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn emit(event: &impl Serialize) {
    match serde_json::to_string(event) {
        Ok(json) => eprintln!("{PREFIX}{json}"),
        Err(error) => eprintln!("[glaurung-pipeline-profile-error] {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_stage_profiling_is_a_transparent_wrapper() {
        let mut profiler = FunctionProfiler {
            enabled: false,
            function: "f".into(),
            entry_va: 0x1000,
        };

        assert_eq!(profiler.measure("identity", || 42), 42);
    }

    #[test]
    fn object_parse_adapter_counts_attempts_only_inside_an_active_run() {
        OBJECT_PARSE_TOTAL.with(|count| count.set(0));
        ACTIVE_RUNS.with(|active| active.set(0));
        assert!(parse_object(b"not an object").is_err());
        assert_eq!(OBJECT_PARSE_TOTAL.with(Cell::get), 0);

        ACTIVE_RUNS.with(|active| active.set(1));
        assert!(parse_object(b"still not an object").is_err());
        assert!(parse_object(b"nor this").is_err());
        ACTIVE_RUNS.with(|active| active.set(0));
        assert_eq!(OBJECT_PARSE_TOTAL.with(Cell::get), 2);
    }

    #[test]
    fn profile_events_have_stable_schema_and_integer_durations() {
        let event = StageProfileEvent {
            schema: SCHEMA,
            event: "stage",
            function: "main",
            entry_va: "0x401000".into(),
            stage: "lower",
            duration_ns: 17,
        };
        let value = serde_json::to_value(event).expect("profile event serializes");

        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["event"], "stage");
        assert_eq!(value["duration_ns"], 17);
    }

    #[test]
    fn nested_runs_have_independent_counts_and_the_outer_run_includes_inner_work() {
        OBJECT_PARSE_TOTAL.with(|count| count.set(0));
        ACTIVE_RUNS.with(|active| active.set(0));
        let outer = RunProfiler {
            enabled: true,
            entry_point: "outer",
            started: Instant::now(),
            parse_total_at_start: 0,
        };
        ACTIVE_RUNS.with(|active| active.set(1));
        assert!(parse_object(b"outer parse").is_err());
        let inner = RunProfiler {
            enabled: true,
            entry_point: "inner",
            started: Instant::now(),
            parse_total_at_start: OBJECT_PARSE_TOTAL.with(Cell::get),
        };
        ACTIVE_RUNS.with(|active| active.set(2));
        assert!(parse_object(b"inner parse").is_err());

        assert_eq!(inner.object_parse_count(), 1);
        assert_eq!(outer.object_parse_count(), 2);
        std::mem::forget(inner);
        std::mem::forget(outer);
        ACTIVE_RUNS.with(|active| active.set(0));
    }
}
