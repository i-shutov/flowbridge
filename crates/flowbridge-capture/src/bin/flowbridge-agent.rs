//! Original Rust native agent entrypoint. No service installation or SSH launch.
use flowbridge_capture::capture_agent;
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command] if command == "status" || command == "--preflight" => Ok(capture_agent::status()),
        [command] if command == "capabilities" => Ok(capture_agent::capabilities()),
        [command] if command == "owner-selftest" => capture_agent::owner_self_test(),
        #[cfg(windows)]
        [command, config_path] if command == "service-stage" => {
            flowbridge_capture::windows_service_management::stage(config_path)
        }
        #[cfg(windows)]
        [command, old_config, new_config] if command == "service-replace" => {
            flowbridge_capture::windows_service_management::replace(old_config, new_config)
        }
        #[cfg(windows)]
        [command, config_path] if command == "service-remove" => {
            flowbridge_capture::windows_service_management::remove(config_path)
        }
        #[cfg(windows)]
        [command, config_path] if command == "service-run" => {
            flowbridge_capture::windows_service::run(config_path)
        }
        [command, config_path] if command == "control-serve" => {
            flowbridge_capture::control_plane::serve_foreground(config_path)
        }
        [command, action] if command == "control" => {
            flowbridge_capture::control_plane::command(action)
        }
        [command, request] if command == "lab" && request.len() <= 4096 => {
            serde_json::from_str(request).map_err(|e| e.to_string()).and_then(capture_agent::run_lab)
        }
        #[cfg(all(windows, target_pointer_width = "64"))]
        [command, local, target] if command == "native-child" => {
            local.parse::<std::net::Ipv4Addr>()
                .map_err(|_| "Invalid child local IPv4".to_owned())
                .and_then(|local| {
                    target
                        .parse::<std::net::SocketAddrV4>()
                        .map_err(|_| "Invalid child target".to_owned())
                        .and_then(|target| flowbridge_capture::self_redirect::run_child(local, target))
                })
        }
        [command, request] if command == "native-self-redirect" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::self_redirect::run)
        }
        [command, request] if command == "relay-probe" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::relay_probe::run)
        }
        _ => Err("Usage: flowbridge-agent status | capabilities | owner-selftest | control-serve <explicit config path> | service-run <absolute loopback config> | service-stage <absolute config> | service-replace <old absolute config> <new absolute config> | service-remove <absolute config> | control <status|reload|stop> | lab <bounded JSON> | relay-probe <loopback JSON>. Protected redirect is unavailable.".to_owned()),
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
