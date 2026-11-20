//! R219: user-mode-only Rust model of R19 AUTH current-AppId semantics.
//! No Windows APIs, sockets, drivers, network access, or claims of WFP proof.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum App { Selected, Broker, ValidThird, Malformed }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto { Tcp, Udp }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Peer { LoopbackBroker, ExternalSsh, ExternalOther }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision { NotScoped, Permit, Block }
#[derive(Clone, Copy)]
struct Flow {
    original: App, current: App, proto: Proto, peer: Peer,
    redirected: bool, reauthorize: bool, origin_pid_ok: bool, ticket_ok: bool,
}

// Abstraction: App::ValidThird represents a well-formed UTF-16 current AppId
// different from both selected EXE and broker; App::Malformed represents a
// value rejected by the R19 auth_appid::valid_utf16_units predicate.
fn r19_scoped(f: Flow) -> bool {
    f.original == App::Selected && f.proto == Proto::Tcp
}
fn r19_model_decision(f: Flow) -> Decision {
    if !r19_scoped(f) { return Decision::NotScoped; }
    let current_syntactically_valid = f.current != App::Malformed;
    if current_syntactically_valid
        && f.redirected && !f.reauthorize
        && f.peer == Peer::LoopbackBroker
        && f.origin_pid_ok && f.ticket_ok
    { Decision::Permit } else { Decision::Block }
}
fn original_leg() -> Flow {
    Flow { original: App::Selected, current: App::Selected,
        proto: Proto::Tcp, peer: Peer::LoopbackBroker,
        redirected: true, reauthorize: false, origin_pid_ok: true, ticket_ok: true }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn original_leg_permitted_in_abstract_model() {
        assert_eq!(r19_model_decision(original_leg()), Decision::Permit);
    }
    #[test] fn valid_third_current_app_is_not_an_identity_check() {
        let mut f = original_leg(); f.current = App::ValidThird;
        assert_eq!(r19_model_decision(f), Decision::Permit);
    }
    #[test] fn malformed_current_app_is_rejected() {
        let mut f = original_leg(); f.current = App::Malformed;
        assert_eq!(r19_model_decision(f), Decision::Block);
    }
    #[test] fn original_identity_remains_authoritative() {
        let mut f = original_leg(); f.original = App::Broker;
        assert_eq!(r19_model_decision(f), Decision::NotScoped);
    }
    #[test] fn external_record_tagged_ssh_still_blocks_conditionally() {
        let mut f = original_leg(); f.current = App::Broker;
        f.peer = Peer::ExternalSsh;
        assert_eq!(r19_model_decision(f), Decision::Block);
    }
    #[test] fn direct_tcp_and_udp_boundary() {
        let mut f = original_leg(); f.redirected = false; f.peer = Peer::ExternalOther;
        assert_eq!(r19_model_decision(f), Decision::Block);
        f.proto = Proto::Udp;
        assert_eq!(r19_model_decision(f), Decision::NotScoped);
    }
    #[test] fn reauthorize_and_missing_provenance_reject() {
        let mut f = original_leg(); f.reauthorize = true;
        assert_eq!(r19_model_decision(f), Decision::Block);
        f.reauthorize = false; f.ticket_ok = false;
        assert_eq!(r19_model_decision(f), Decision::Block);
    }
}
