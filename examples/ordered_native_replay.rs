use std::path::Path;

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 5 {
        eprintln!(
            "usage: {} TRACE_DIR FINDING_SHA256 OFFLINE_REPLAY_SHA256 OUTPUT_JSON",
            arguments
                .first()
                .map_or("ordered_native_replay", String::as_str)
        );
        std::process::exit(2);
    }
    if let Err(error) = glaurung::symbolic::ordered_replay::replay_to_report(
        Path::new(&arguments[1]),
        &arguments[2],
        &arguments[3],
        Path::new(&arguments[4]),
    ) {
        eprintln!("ordered native replay failed: {error}");
        std::process::exit(1);
    }
}
