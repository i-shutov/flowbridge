//! Original Rust native agent entrypoint. No service installation or SSH launch.
use flowbridge_capture::capture_agent;
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command] if command == "status" || command == "--preflight" => Ok(capture_agent::status()),
        [command] if command == "capabilities" => Ok(capture_agent::capabilities()),
        [command] if command == "owner-selftest" => capture_agent::owner_self_test(),
        [command] if command == "udp-owner-selftest" => capture_agent::udp_owner_self_test(),
        #[cfg(windows)]
        [command] if command == "wfp-readonly" => Ok(flowbridge_capture::windows_wfp_readonly::report()),
        #[cfg(windows)]
        [command, path, port, consent] if command == "wfp-qa-guard" => {
            port.parse::<u16>().map_err(|_| "Invalid WFP QA port".to_owned())
                .and_then(|p| flowbridge_capture::windows_wfp_dynamic_lab::guard(path, p, consent))
        }
        #[cfg(windows)]
        [command, path, consent] if command == "wfp-qa-identity" => {
            flowbridge_capture::windows_wfp_dynamic_lab::identity_probe(path, consent)
        }
        #[cfg(windows)]
        [command, selected, other, port, consent] if command == "wfp-qa-event-identity" => {
            port.parse::<u16>()
                .map_err(|_| "Invalid WFP QA event port".to_owned())
                .and_then(|p| {
                    flowbridge_capture::windows_wfp_dynamic_lab::event_identity_probe(
                        selected, other, p, consent,
                    )
                })
        }
        #[cfg(windows)]
        [command, port, consent] if command == "wfp-qa-client" => {
            port.parse::<u16>().map_err(|_| "Invalid WFP QA port".to_owned())
                .and_then(|p| flowbridge_capture::windows_wfp_dynamic_lab::client(p, consent))
        }
        #[cfg(windows)]
        [command, address, port, consent] if command == "wfp-qa-client-local-ipv4" => {
            port.parse::<u16>().map_err(|_| "Invalid WFP QA local-interface port".to_owned())
                .and_then(|p| flowbridge_capture::windows_wfp_dynamic_lab::client_local_interface_ipv4(address, p, consent))
        }
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
        [command, old_config, next_executable, next_config, expected_sha256]
            if command == "service-binary-replace" =>
        {
            flowbridge_capture::windows_service_management::binary_replace(
                old_config, next_executable, next_config, expected_sha256,
            )
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
        [command, request] if command == "udp-testnet-drop-lab" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::udp_quarantine::run)
        }
        [command, request] if command == "udp6-testnet-drop-lab" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::udp6_quarantine::run)
        }
        [command, request] if command == "dns-udp-lab" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::dns_stub::run)
        }
        [command, request] if command == "relay-probe" && request.len() <= 4096 => {
            serde_json::from_str(request)
                .map_err(|e| e.to_string())
                .and_then(flowbridge_capture::relay_probe::run)
        }
        _ => Err("Usage: flowbridge-agent status | capabilities | owner-selftest | udp-owner-selftest | control-serve <explicit config path> | service-run <absolute loopback config> | service-stage <absolute config> | service-replace <old absolute config> <new absolute config> | service-remove <absolute config> | service-binary-replace <old config> <next sibling x64 exe> <new config> <sha256> | control <status|reload|stop> | lab <bounded JSON> | relay-probe <loopback JSON> | dns-udp-lab <explicit local SOCKS DNS JSON> | udp-testnet-drop-lab <bounded self-owned IPv4 UDP or separately consented fragmentation TEST-NET DROP JSON> | udp6-testnet-drop-lab <explicit IPv6 signed-driver drop JSON>. Protected redirect is unavailable.".to_owned()),
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
