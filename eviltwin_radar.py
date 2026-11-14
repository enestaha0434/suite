#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EvilTwinRadar - SSID ve Erişim Noktası Envanteri
Geliştirici: ENESxAİs
SSID ve BSSID sayılarını listeler; erişim noktalarının gerçekliğini doğrulamaz.
"""

import os
import sys
import subprocess
import re

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler eksik: pip install rich pyfiglet")
    input("\nÇıkmak için Enter'a basın...")
    sys.exit(1)

console = Console()


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("EvilTwin Radar", font="slant")
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[dim red]SSID ve Erişim Noktası Envanteri | ENESxAİs[/dim red]\n")


def scan_evil_twins():
    console.print("[bold yellow]→ Çevredeki Wi-Fi sinyalleri ve BSSID (MAC) adresleri taranıyor...[/bold yellow]")
    try:
        res = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        console.print(f"[yellow]Wi-Fi envanteri alınamadı: {e}[/yellow]")
        return

    ssid_bssid_map = {}
    current_ssid = ""

    for line in res.stdout.splitlines():
        line = line.strip()
        ssid = re.match(r'^SSID\s+\d+\s*:\s*(.*)$', line, re.IGNORECASE)
        bssid = re.match(r'^BSSID\s+\d+\s*:\s*([0-9a-f: -]{17})', line, re.IGNORECASE)
        if ssid:
            current_ssid = ssid.group(1).strip() or "[Gizli Ağ]"
            ssid_bssid_map.setdefault(current_ssid, set())
        elif bssid and current_ssid:
            ssid_bssid_map[current_ssid].add(bssid.group(1).strip().lower())

    table = Table(title="Wi-Fi Ağları ve Erişim Noktası (BSSID) Analizi")
    table.add_column("SSID (Ağ Adı)", style="bold cyan")
    table.add_column("Tespit Edilen AP Sayısı", style="yellow")
    table.add_column("Güvenlik Durumu", style="bold")

    evil_twin_found = False
    for ssid, bssids in ssid_bssid_map.items():
        if len(bssids) > 1:
            table.add_row(ssid, str(len(bssids)), "[bold yellow]ÇOKLU ERİŞİM NOKTASI (Mesh veya Evil Twin Şüphesi)[/bold yellow]")
            evil_twin_found = True
        else:
            table.add_row(ssid, str(len(bssids)), "[yellow]Tek erişim noktası görüldü; güvenilirlik doğrulanmadı[/yellow]")

    console.print(table)
    if not ssid_bssid_map or not any(ssid_bssid_map.values()):
        console.print('[yellow]Erişim noktası verisi okunamadı veya ağ bulunamadı; değerlendirme yapılamaz.[/yellow]')
        return
    if evil_twin_found:
        console.print(Panel(
            "[bold yellow]DİKKAT:[/bold yellow] Aynı ağ adına (SSID) sahip birden fazla sinyal tespit edildi!\n"
            "Eğer bir mesh ağında değilseniz (evde tek modem varsa), biri sahte bir Wi-Fi tuzağı (Evil Twin)\n"
            "açarak şifrelerinizi ve trafiğinizi dinlemeye çalışıyor olabilir.",
            title="[bold yellow]Evil Twin Uyarısı[/bold yellow]", border_style="yellow"
        ))
    else:
        console.print("[bold green]Çoklu erişim noktası gözlenmedi; bu sonuç ağların güvenilir olduğunu doğrulamaz.[/bold green]")


def main():
    display_banner()
    scan_evil_twins()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
