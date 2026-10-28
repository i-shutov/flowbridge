from pathlib import Path

def edit(path, old, new):
    p=Path(path); s=p.read_text(encoding='utf-8')
    if s.count(old)!=1: raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='tests/ssh_real_integration.py'
edit(p,'    daemon = None','    daemon = capture = None')
edit(p,"            require(len({ssh_port, socks_port, engine_port, target_port}) == 4, 'Port collision')",'''            require(len({ssh_port, socks_port, engine_port, target_port}) == 4, 'Port collision')
            capture_log = (args.output / 'capture.log').open('wb')
            capture = subprocess.Popen(['sudo', '-n', 'tcpdump', '-i', 'lo', '-nn', '-s', '256', '-U',
                '-w', str((args.output / 'socks.pcap').resolve()), 'tcp', 'port', str(socks_port)],
                stdout=capture_log, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(0.2)
            require(capture.poll() is None, 'SOCKS packet capture did not start')''')
edit(p,'            server_log.close()','''            if capture:
                subprocess.run(['sudo', '-n', 'kill', '-INT', '--', f'-{capture.pid}'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                capture.wait(timeout=10)
                capture_log.close()
                with (args.output / 'socks-wire.txt').open('wb') as wire:
                    subprocess.run(['sudo', '-n', 'tcpdump', '-nn', '-tttt', '-XX', '-r',
                        str((args.output / 'socks.pcap').resolve())], stdout=wire,
                        stderr=subprocess.STDOUT, timeout=10, check=False)
            server_log.close()''')
edit(p,"'verbose_diagnostics': repetition % 2 == 1", "'verbose_diagnostics': False")
print('Isolated loopback SOCKS capture added; production logging, first failure remains fatal')
