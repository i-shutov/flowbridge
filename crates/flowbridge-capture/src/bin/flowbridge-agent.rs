//! Original Rust native agent entrypoint. No service installation or SSH launch.
use flowbridge_capture::capture_agent;
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command] if command == "status" || command == "--preflight" => Ok(capture_agent::status()),
        [command] if command == "capabilities" => Ok(capture_agent::capabilities()),
        [command, request] if command == "lab" && request.len() <= 4096 => {
            serde_json::from_str(request).map_err(|e| e.to_string()).and_then(capture_agent::run_lab)
        }
        [command, request] if command == "relay-probe" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::relay_probe::run)
        }
        _ => Err("Usage: flowbridge-agent status | capabilities | lab <bounded JSON> | relay-probe <loopback JSON>. Protected redirect is not yet accepted.".to_owned()),
    };
    match result {
        Ok(value) => {
            println!("{}", value);
            if value
                .get("loop_completed")
                .is_some_and(|v| v.as_bool() != Some(true))
                || value
                    .get("rollback_confirmed")
                    .is_some_and(|v| v.as_bool() != Some(true))
            {
                std::process::exit(1);
            }
        }
        Err(error) => {
            println!(
                "{}",
                json!({"ok":false,"error":error,"release_accepted":false})
            );
            std::process::exit(1);
        }
    }
}
