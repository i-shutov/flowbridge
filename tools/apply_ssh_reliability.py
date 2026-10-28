from pathlib import Path

def edit(path, old, new):
    p=Path(path); s=p.read_text(encoding='utf-8')
    if s.count(old)!=1: raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='crates/flowbridge-tunnel/src/lib.rs'
edit(p,'    pub compression: bool,','    pub compression: bool,\n    pub verbose_diagnostics: bool,')
edit(p,'            compression: false,','            compression: false,\n            verbose_diagnostics: false,')
edit(p,'            "LogLevel=ERROR".into(),','            format!("LogLevel={}", if self.verbose_diagnostics { "DEBUG3" } else { "ERROR" }),')
p='tests/ssh_real_integration.py'
edit(p,'def main():','def main(repetition=0):')
edit(p,'    args = parser.parse_args()','    args = parser.parse_args()\n    args.output = args.output / f"iteration-{repetition + 1:02d}"')
edit(p,"'AllowAgentForwarding no', 'LogLevel VERBOSE',","'AllowAgentForwarding no', 'LogLevel DEBUG3',")
edit(p,"'local_port': socks_port, 'identity_file': str(root / 'client_key'),","'local_port': socks_port, 'verbose_diagnostics': True, 'identity_file': str(root / 'client_key'),")
edit(p,"if __name__ == '__main__':\n    main()","if __name__ == '__main__':\n    for repetition in range(10):\n        main(repetition)")
print('Verbose opt-in diagnostics and ten isolated integration iterations enabled')
