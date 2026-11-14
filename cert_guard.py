#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CertGuard - Sahte Kök Sertifika & SSL Casusu Avcısı (Root CA Hunter)
Geliştirici: ENESxAİs
Yerel makine kök sertifikalarını inceleme için listeler.
"""

import os
import sys
import subprocess

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
    banner = pyfiglet.figlet_format("CertGuard", font="slant")
    console.print(f"[bold yellow]{banner}[/bold yellow]")
    console.print("[dim yellow]Windows Kök Sertifika Envanteri | ENESxAİs[/dim yellow]\n")


def scan_root_certificates():
    """Kökleri parmak iziyle listeler; adlarına göre güvenilirlik kararı vermez."""
    import csv
    import io
    ps_cmd = "Get-ChildItem -Path Cert:\\LocalMachine\\Root | Select-Object Subject,Issuer,Thumbprint,NotAfter | ConvertTo-Csv -NoTypeInformation"
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, check=True)
        rows = list(csv.DictReader(io.StringIO(res.stdout)))
        table = Table(title="Yerel makine kök sertifika envanteri")
        for name in ("Konu", "Sağlayıcı", "SHA-1 parmak izi", "Son kullanım"):
            table.add_column(name)
        for row in rows:
            table.add_row(row.get('Subject', ''), row.get('Issuer', ''), row.get('Thumbprint', ''), row.get('NotAfter', ''))
        console.print(table)
        console.print(f"{len(rows)} sertifika listelendi. İsim ve parmak izi tek başına güvenilirlik kanıtlamaz; güvenilir kaynaklarla karşılaştırın. Kullanıcı sertifika deposu bu listede yoktur.")
    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            console.print(f"[yellow]Komut hatası: {e.stderr.strip()}[/yellow]")
        console.print(f"[red]Sertifika envanteri alınamadı: {e}[/red]")


def main():
    display_banner()
    scan_root_certificates()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
