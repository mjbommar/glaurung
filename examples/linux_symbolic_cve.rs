//! Execute one strictly admitted Linux AArch64 ioctl handler with Axeyum.

use std::collections::BTreeMap;
use std::path::PathBuf;

use glaurung::analysis::linux_symbolic_frontend::admit_linux_aarch64_handler;
use glaurung::symbolic::{
    canonical_model_choice_stats, execution_path_stats, exploration_limit_stats,
    find_linux_ioctl_sinks_for_command_with_apis, find_linux_ioctl_sinks_with_apis,
    linux_driver_api_model, linux_local_api_model, reset_execution_path_stats,
    reset_exploration_limit_stats, LinuxIoctlEnvironment, Severity,
};
use serde::Serialize;

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    object: String,
    handler: String,
    solver: &'static str,
    max_states: usize,
    command: Option<u32>,
    environment: &'static str,
    admitted: bool,
    execution_acceptable: bool,
    error: Option<String>,
    external_calls: usize,
    modeled_external_calls: usize,
    local_calls: usize,
    modeled_local_calls: usize,
    sinks: Vec<SinkReport>,
    exploration: ExplorationReport,
    path_stops: PathStopReport,
    concretization: ConcretizationReport,
}

#[derive(Serialize)]
struct SinkReport {
    va: u64,
    kind: String,
    severity: String,
    tainted_by: Vec<String>,
    witness: BTreeMap<u32, String>,
}

#[derive(Serialize, Default)]
struct ExplorationReport {
    runs: u64,
    completed: u64,
    state_budget: u64,
    solve_budget: u64,
    timeout_budget: u64,
    deadline: u64,
}

#[derive(Serialize, Default)]
struct PathStopReport {
    returned: u64,
    traps: BTreeMap<String, u64>,
    off_cfg: u64,
    loop_limit: u64,
    model_unavailable: u64,
    unresolved_symbolic_memory: u64,
    unsupported_intrinsics: BTreeMap<String, u64>,
    residual_unknowns: BTreeMap<String, u64>,
    unexpected_fork: u64,
    budget_exhausted: u64,
    unexpected_flow: u64,
    unmodeled_calls: BTreeMap<u64, u64>,
    stop_sites: BTreeMap<u64, BTreeMap<String, u64>>,
    memory_access_sites: BTreeMap<u64, u64>,
    low_page_access_sites: BTreeMap<u64, u64>,
    concrete_access_addresses: BTreeMap<u64, BTreeMap<u64, u64>>,
}

#[derive(Serialize, Default)]
struct ConcretizationReport {
    policy: String,
    attempts: u64,
    completed: u64,
    inconclusive: u64,
    unknown: u64,
    no_solver: u64,
    error: u64,
}

fn emit(report: &Report) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|error| format!("cannot serialize report: {error}"))?;
    println!("{json}");
    Ok(())
}

fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|error| error.to_string())
    } else {
        value.parse::<u32>().map_err(|error| error.to_string())
    }
}

fn parse_environment(value: &str) -> Result<LinuxIoctlEnvironment, String> {
    match value {
        "generic" => Ok(LinuxIoctlEnvironment::Generic),
        "pci-endpoint-test" => Ok(LinuxIoctlEnvironment::PciEndpointTest),
        _ => Err(format!("unknown Linux ioctl environment `{value}`")),
    }
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(object_path) = args.next().map(PathBuf::from) else {
        eprintln!(
            "usage: linux_symbolic_cve <object> <handler> [max-states] [command] [environment]"
        );
        std::process::exit(2);
    };
    let Some(handler) = args.next().and_then(|value| value.into_string().ok()) else {
        eprintln!(
            "usage: linux_symbolic_cve <object> <handler> [max-states] [command] [environment]"
        );
        std::process::exit(2);
    };
    let max_states = match args.next() {
        Some(value) => match value.to_string_lossy().parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                eprintln!("max-states must be a positive integer");
                std::process::exit(2);
            }
        },
        None => 4096,
    };
    let command = match args.next() {
        Some(value) => match parse_u32(&value.to_string_lossy()) {
            Ok(value) => Some(value),
            Err(error) => {
                eprintln!("command must be a decimal or 0x-prefixed u32: {error}");
                std::process::exit(2);
            }
        },
        None => None,
    };
    let environment = match args.next() {
        Some(value) => match parse_environment(&value.to_string_lossy()) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        },
        None => LinuxIoctlEnvironment::Generic,
    };
    if args.next().is_some() {
        eprintln!(
            "usage: linux_symbolic_cve <object> <handler> [max-states] [command] [environment]"
        );
        std::process::exit(2);
    }

    let object_name = object_path.display().to_string();
    let data = match std::fs::read(&object_path) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("cannot read {}: {error}", object_path.display());
            std::process::exit(2);
        }
    };
    let admitted = match admit_linux_aarch64_handler(&data, &handler) {
        Ok(admitted) => admitted,
        Err(error) => {
            let report = Report {
                schema: "glaurung-linux-symbolic-cve-v2",
                object: object_name,
                handler,
                solver: "axeyum-qfbv",
                max_states,
                command,
                environment: environment.id(),
                admitted: false,
                execution_acceptable: false,
                error: Some(error.to_string()),
                external_calls: 0,
                modeled_external_calls: 0,
                local_calls: 0,
                modeled_local_calls: 0,
                sinks: Vec::new(),
                exploration: ExplorationReport::default(),
                path_stops: PathStopReport::default(),
                concretization: ConcretizationReport::default(),
            };
            if let Err(error) = emit(&report) {
                eprintln!("{error}");
            }
            std::process::exit(1);
        }
    };

    let external_apis = linux_driver_api_model(&admitted.external_calls);
    let local_apis = linux_local_api_model(&admitted.local_calls);
    let mut apis = external_apis.clone();
    apis.extend(local_apis.clone());
    reset_exploration_limit_stats();
    reset_execution_path_stats();
    let raw_sinks = match command {
        Some(command) => find_linux_ioctl_sinks_for_command_with_apis(
            &admitted.llir,
            command,
            environment,
            &apis,
            max_states,
        ),
        None => find_linux_ioctl_sinks_with_apis(&admitted.llir, &apis, max_states),
    };
    let mut sinks = raw_sinks
        .into_iter()
        .map(|sink| SinkReport {
            va: sink.va,
            kind: format!("{:?}", sink.kind),
            severity: match sink.severity {
                Severity::Arbitrary => "arbitrary".to_string(),
                Severity::Constrained => "constrained".to_string(),
            },
            tainted_by: sink.tainted_by,
            witness: sink
                .witness
                .values
                .into_iter()
                .map(|(symbol, value)| (symbol, format!("0x{value:x}")))
                .collect(),
        })
        .collect::<Vec<_>>();
    sinks.sort_by(|left, right| {
        left.va
            .cmp(&right.va)
            .then(left.kind.cmp(&right.kind))
            .then(left.tainted_by.cmp(&right.tainted_by))
            .then(left.witness.cmp(&right.witness))
    });
    let limits = exploration_limit_stats();
    let paths = execution_path_stats();
    let choices = canonical_model_choice_stats();
    let execution_acceptable = limits.runs > 0
        && limits.runs == limits.completed
        && limits.state_budget == 0
        && limits.solve_budget == 0
        && limits.timeout_budget == 0
        && limits.deadline == 0
        && paths.incomplete_stops() == 0
        && paths.modeled_terminal_paths() > 0;
    let report = Report {
        schema: "glaurung-linux-symbolic-cve-v2",
        object: object_name,
        handler,
        solver: "axeyum-qfbv",
        max_states,
        command,
        environment: environment.id(),
        admitted: true,
        execution_acceptable,
        error: None,
        external_calls: admitted.external_calls.len(),
        modeled_external_calls: external_apis.len(),
        local_calls: admitted.local_calls.len(),
        modeled_local_calls: local_apis.len(),
        sinks,
        exploration: ExplorationReport {
            runs: limits.runs,
            completed: limits.completed,
            state_budget: limits.state_budget,
            solve_budget: limits.solve_budget,
            timeout_budget: limits.timeout_budget,
            deadline: limits.deadline,
        },
        path_stops: PathStopReport {
            returned: paths.returned,
            traps: paths.traps,
            off_cfg: paths.off_cfg,
            loop_limit: paths.loop_limit,
            model_unavailable: paths.model_unavailable,
            unresolved_symbolic_memory: paths.unresolved_symbolic_memory,
            unsupported_intrinsics: paths.unsupported_intrinsics,
            residual_unknowns: paths.residual_unknowns,
            unexpected_fork: paths.unexpected_fork,
            budget_exhausted: paths.budget_exhausted,
            unexpected_flow: paths.unexpected_flow,
            unmodeled_calls: paths.unmodeled_calls,
            stop_sites: paths.stop_sites,
            memory_access_sites: paths.memory_access_sites,
            low_page_access_sites: paths.low_page_access_sites,
            concrete_access_addresses: paths.concrete_access_addresses,
        },
        concretization: ConcretizationReport {
            policy: choices.policy.to_string(),
            attempts: choices.attempts,
            completed: choices.completed,
            inconclusive: choices.inconclusive,
            unknown: choices.unknown,
            no_solver: choices.no_solver,
            error: choices.error,
        },
    };
    if let Err(error) = emit(&report) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
