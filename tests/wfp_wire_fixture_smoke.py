#!/usr/bin/env python3
"""Run real dual-stack SOCKS5 wire/echo fixtures without WFP or a kernel driver.

Executed on hosted Linux, Windows and macOS CI. It proves the test fixture
supports IPv4/IPv6, byte-for-byte echo, EOF, refusal and UDP baseline; it does
NOT claim that a WFP driver was loaded or OS traffic was intercepted.
"""
import argparse
import json
from pathlib import Path
import socket
import time

from windows_wfp_redirect_runtime import (
    Echo, Server, V6Server, UDP, UDPServer, V6UDPServer,
    Socks, exact, require, start,
)


def socks_exchange(port, family, address, *, denied=False):
    payload = b'flowbridge-real-wire\x00\xff' + bytes(range(256)) * 2
    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b'\x05\x01\x00')
        require(exact(client, 2) == b'\x05\x00', 'SOCKS method mismatch')
        atyp = b'\x01' if family == socket.AF_INET else b'\x04'
        client.sendall(b'\x05\x01\x00' + atyp +
                       socket.inet_pton(family, address[0]) +
                       int(address[1]).to_bytes(2, 'big'))
        result = exact(client, 10)
        require(result[0] == 5, 'SOCKS reply version mismatch')
        if denied:
            require(result[1] == 5, 'SOCKS mock should deny CONNECT without fallback')
            return
        require(result[1] == 0, 'SOCKS mock did not accept exact target')
        client.sendall(payload)
        require(exact(client, len(payload)) == payload, 'SOCKS echo altered payload')
        client.shutdown(socket.SHUT_WR)
        require(client.recv(1) == b'', 'SOCKS half-close was not propagated')


def udp_exchange(family, target):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        payload = b'\x00\xffUDP' + bytes(range(64))
        sock.sendto(payload, target)
        echoed, origin = sock.recvfrom(512)
        require(echoed == payload, 'UDP echo changed payload')
        require(origin[1] == target[1], 'UDP response came from an unexpected port')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'passed': False, 'real_wfp_driver_loaded': False,
              'real_os_interception_tested': False,
              'loopback_only': True, 'checks': []}
    running = []
    try:
        targets = {}
        datagrams = {}
        for family, host, tcp_type, udp_type in (
            (socket.AF_INET, '127.0.0.1', Server, UDPServer),
            (socket.AF_INET6, '::1', V6Server, V6UDPServer),
        ):
            echo = tcp_type((host, 0), Echo)
            running.append((echo, start(echo)))
            targets[family] = (host, echo.server_address[1])
            udp = udp_type((host, 0), UDP)
            running.append((udp, start(udp)))
            datagrams[family] = (host, udp.server_address[1])
        socks = Server(('127.0.0.1', 0), Socks)
        socks.echo_ports = targets
        running.append((socks, start(socks)))
        for family in (socket.AF_INET, socket.AF_INET6):
            socks_exchange(socks.server_address[1], family, targets[family])
            udp_exchange(family, datagrams[family])
            require(socks.connects_by_family[family] == 1,
                    'SOCKS fixture did not record exactly one matching address-family CONNECT')
        report['checks'].append('Real IPv4/IPv6 SOCKS CONNECT bytes and binary TCP/UDP echo')
        report['checks'].append('TCP half-close/EOF on both address families')
        socks.deny = True
        for family in (socket.AF_INET, socket.AF_INET6):
            socks_exchange(socks.server_address[1], family, targets[family], denied=True)
            require(socks.connects_by_family[family] == 2,
                    'SOCKS deny did not record the selected destination family')
        report['checks'].append('SOCKS denial returns a real negative reply without connecting DIRECT')
        report['counts'] = {
            'ipv4': socks.connects_by_family[socket.AF_INET],
            'ipv6': socks.connects_by_family[socket.AF_INET6],
        }
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for server, thread in running:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
