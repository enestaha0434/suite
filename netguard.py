#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetGuard - Canlı Ağ Radarı & Casus Bağlantı Dedektörü (Mini IDS)
Geliştirici: ENESxAİs
"""

import os
import sys
import subprocess
import time
import ipaddress
from datetime import datetime
from typing import Dict, Set

# Otomatik Bağımlılık Kurucu
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler (rich, pyfiglet) bu Python ortamında eksik.")
    ans = input("Otomatik olarak şimdi yüklensin mi? (e/h): ").strip().lower()
    if ans in ["e", "evet", "y", "yes", ""]:
        print("Kütüphaneler yükleniyor, lütfen bekleyin...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "pyfiglet"])
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        import pyfiglet
    else:
        sys.exit(1)

console = Console()


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("NetGuard", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Canlı Ağ Radarı & Şüpheli Dış Bağlantı Dedektörü | ENESxAİs[/dim cyan]\n")


def get_process_name_by_pid(pid: str) -> str:
    try:
        res = subprocess.run(["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"], capture_output=True, text=True)
        lines = res.stdout.strip().splitlines()
        if lines and "," in lines[0]:
            pname = lines[0].split(",")[0].replace('"', '')
            return pname
    except Exception:
        pass
    return "Bilinmeyen Program"


def get_active_connections() -> Dict[str, Dict]:
    connections = {}
    try:
        res = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            if "ESTABLISHED" in line:
                parts = line.split()
                if len(parts) >= 4:
                    local_ip, remote_ip, pid = parts[1], parts[2], parts[-1]
                    address = remote_ip.rsplit(":", 1)[0].strip("[]")
                    if ipaddress.ip_address(address).is_global:
                        conn_key = f"{local_ip}_{remote_ip}_{pid}"
                        connections[conn_key] = {
                            "local": local_ip,
                            "remote": remote_ip,
                            "pid": pid,
                            "time": datetime.now().strftime("%H:%M:%S")
                        }
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise RuntimeError(f"TCP bağlantıları okunamadı: {exc}") from exc
    return connections


def live_network_monitor():
    display_banner()
    console.print(Panel(
        "[bold green]Canlı Ağ Radarı Devrede![/bold green]\n"
        "Yerleşik TCP bağlantıları iki saniyede bir sorgulanır; UDP ve kısa bağlantılar kaçabilir.\n"
        "[yellow]Yeni gözlenen genel IP bağlantıları bildirilir; zararlı oldukları doğrulanmaz.[/yellow]\n"
        "[dim]Durdurmak için CTRL+C tuşlarına basabilirsiniz.[/dim]",
        title="[bold cyan]NetGuard Canlı İzleme[/bold cyan]",
        border_style="cyan"
    ))

    known_conns: Set[str] = set()
    initial_run = True

    try:
        while True:
            current_conns = get_active_connections()

            for ckey, info in current_conns.items():
                if ckey not in known_conns:
                    known_conns.add(ckey)
                    if not initial_run:
                        pname = get_process_name_by_pid(info["pid"])
                        console.print(Panel(
                            f"[bold red]🚨 YENİ DIŞ BAĞLANTI TESPİT EDİLDİ![/bold red]\n\n"
                            f"Program: [bold yellow]{pname}[/bold yellow] (PID: [cyan]{info['pid']}[/cyan])\n"
                            f"Bağlanılan Dış IP: [bold red]{info['remote']}[/bold red]\n"
                            f"Yerel Port: {info['local']}\n"
                            f"Zaman: {info['time']}",
                            title="[bold red]NetGuard Alarm[/bold red]",
                            border_style="red"
                        ))

            if initial_run:
                table = Table(title=f"Şu An İnternete Bağlı Olan Programlar ({len(current_conns)} Bağlantı)")
                table.add_column("Program Adı", style="bold green", width=22)
                table.add_column("PID", style="yellow", width=8)
                table.add_column("Dış Hedef IP : Port", style="bold cyan")
                table.add_column("Yerel Port", style="dim")

                for ckey, info in current_conns.items():
                    pname = get_process_name_by_pid(info["pid"])
                    table.add_row(pname, info["pid"], info["remote"], info["local"])

                console.print(table)
                console.print("\n[dim]Radar dinlemede... Yeni bir bağlantı olduğunda burada belirecek.[/dim]")
                initial_run = False

            known_conns = set(current_conns)
            time.sleep(2.0)

    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]NetGuard canlı izleme durduruldu.[/yellow]")
        input("\nÇıkmak için Enter'a basın...")


if __name__ == "__main__":
    try:
        live_network_monitor()
    except KeyboardInterrupt:
        pass
