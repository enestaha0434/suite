#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FirewallAuditor - Windows Güvenlik Duvarı Arka Kapı Avcısı
Geliştirici: ENESxAİs
Zararlı yazılımların Windows Güvenlik Duvarına gizlice eklediği şüpheli izinleri avlar.
"""

import os
import sys
import subprocess
import csv
import io

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
    banner = pyfiglet.figlet_format("Firewall Audit", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Windows Güvenlik Duvarı Arka Kapı Kuralı Avcısı | ENESxAİs[/dim cyan]\n")


def audit_firewall_rules():
    console.print("[bold yellow]→ Windows Güvenlik Duvarı gelen izin kuralları taranıyor...[/bold yellow]")
    ps_cmd = "Get-NetFirewallRule -Enabled True -Direction Inbound | Where-Object {$_.Action -eq 'Allow'} | Select-Object DisplayName, Profile | ConvertTo-Csv -NoTypeInformation"

    try:
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, check=True)
        lines = res.stdout.strip().splitlines()

        table = Table(title="Dışarıdan Girişe İzin Verilen Güvenlik Duvarı Kuralları")
        table.add_column("Kural Adı", style="bold cyan")
        table.add_column("Profil", style="yellow")
        table.add_column("Durum", style="bold")

        suspicious_rules = []
        for parts in list(csv.reader(io.StringIO(res.stdout)))[1:]:
            if len(parts) >= 2:
                rname = parts[0].replace('"', '')
                rprof = parts[1].replace('"', '')

                # Temp, AppData veya bilinmeyen script kuralları
                if "temp" in rname.lower() or "powershell" in rname.lower() or "cmd" in rname.lower():
                    table.add_row(rname, rprof, "[bold red]ŞÜPHELİ KURAL![/bold red]")
                    suspicious_rules.append(rname)
                else:
                    table.add_row(rname, rprof, "[yellow]İsim eşleşmesi yok[/yellow]")

        console.print(table)
        if suspicious_rules:
            console.print(f"[bold red]DİKKAT: Güvenlik duvarında {len(suspicious_rules)} adet şüpheli izin kuralı bulundu![/bold red]")
        else:
            console.print("[bold green]Kural adlarında seçilen kelimeler bulunmadı; kural güvenliği doğrulanmadı.[/bold green]")

    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            console.print(f"[yellow]Komut hatası: {e.stderr.strip()}[/yellow]")
        console.print(f"[bold red]Tarama Hatası:[/bold red] {e}")


def main():
    display_banner()
    audit_firewall_rules()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
