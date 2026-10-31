"""Real cross-process loopback test of original Rust SSH identification diagnostic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading

IDENT=b"SSH-2.0-FlowBridgeProbe_0.2\r\n"
BANNER=b"SSH-2.0-Fixture_1\r\n"
def recv_line(conn):
    data=b""
    while len(data)<255:
        value=conn.recv(1)
        if not value: raise RuntimeError("EOF before identification")
        data+=value
        if value==b"\n": return data
    raise RuntimeError("identification too long")
def run():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    exe=Path("target/debug/flowbridge"+(".exe" if os.name=="nt" else "")).resolve()
    if not exe.is_file(): raise RuntimeError("Compiled CLI unavailable")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));listener.listen(2);listener.settimeout(5)
        cmd=[str(exe),"ssh-diagnose","--endpoint",f"127.0.0.1:{listener.getsockname()[1]}","--timeout-ms","1500"]
        denied=subprocess.run(cmd+["--consent","DENY"],capture_output=True,text=True,timeout=5)
        if denied.returncode==0: raise RuntimeError("No-consent probe accepted")
        errors=[]
        def server():
            try:
                for i in range(2):
                    conn,_=listener.accept()
                    with conn:
                        conn.settimeout(3)
                        if i==0:
                            conn.sendall(BANNER); got=recv_line(conn)
                        else:
                            got=recv_line(conn);conn.sendall(BANNER)
                        if got!=IDENT:raise RuntimeError("Unexpected client identification")
                        conn.sendall(bytes([0,0,0,12,8]))
            except Exception as e:errors.append(str(e))
        thread=threading.Thread(target=server,daemon=True);thread.start()
        result=subprocess.run(cmd+["--consent","DIRECT_SSH_DIAGNOSTIC"],capture_output=True,text=True,timeout=10)
        thread.join(timeout=5)
        if thread.is_alive() or errors or result.returncode:
            raise RuntimeError(f"Failed TCP fixture: {errors} {result.stderr[:200]}")
        data=json.loads(result.stdout)
        if [a["outcome"] for a in data["attempts"]]!=["packet_header_observed","packet_header_observed"]:
            raise RuntimeError("A/B outcomes not observed")
        if data["authentication_attempted"] or data["workaround_proven"] or "127.0.0.1" in result.stdout:
            raise RuntimeError("Invalid diagnostic claim or privacy leak")
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps({
            "passed":True,"actual_tcp_two_orders":True,"no_consent_rejected":True,
            "cli_sha256":hashlib.sha256(exe.read_bytes()).hexdigest(),
            "product_data_path":False,"authenticated":False,"workaround_proven":False,
            "native_win10_11":False},indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":run()
