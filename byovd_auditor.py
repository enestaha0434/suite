#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BYOVDAuditor - Güvenlik Açıklı & İmzalanmamış Sürücü Denetleyicisi
Geliştirici: ENESxAİs
Antivirüsleri devre dışı bırakmak için yüklenen savunmasız çekirdek (Kernel) sürücülerini avlar.
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
    banner = pyfiglet.figlet_format("BYOVD Audit", font="slant")
    console.print(f"[bold yellow]{banner}[/bold yellow]")
    console.print("[dim yellow]Windows Savunmasız Çekirdek Sürücüsü (BYOVD) Avcısı | ENESxAİs[/dim yellow]\n")


def scan_kernel_drivers():
    console.print("[bold yellow]→ Windows çekirdek sürücüleri (driverquery) adları taranıyor (sürüm ve dijital imza doğrulanmaz)...[/bold yellow]")

    # LOLDrivers / Bilinen savunmasız sürücü listesi parçası
    known_vulnerable_drivers = ["gdrv.sys", "mhyprot2.sys", "procexp.sys", "dbutil_2_3.sys", "rtcore64.sys", "ene.sys", "kprocesshacker.sys"]

    try:
        res = subprocess.run(["driverquery", "/v", "/fo", "csv"], capture_output=True, text=True, check=True)
        lines = res.stdout.strip().splitlines()

        table = Table(title="Windows Yüklü Sürücüler Analizi")
        table.add_column("Sürücü Adı", style="bold cyan")
        table.add_column("Açıklama", style="dim")
        table.add_column("Durum", style="bold")

        vuln_found = False
        count = 0

        for parts in list(csv.reader(io.StringIO(res.stdout)))[1:]:
            if len(parts) >= 3:
                dname = parts[0].replace('"', '')
                desc = parts[1].replace('"', '')
                d_file = dname.lower() if dname.lower().endswith(".sys") else f"{dname.lower()}.sys"

                if d_file in known_vulnerable_drivers:
                    table.add_row(dname, desc[:30], "[bold red]İSİM EŞLEŞMESİ: SÜRÜMÜ İNCELEYİN[/bold red]")
                    vuln_found = True
                    count += 1
                else:
                    table.add_row(dname, desc[:30], "[yellow]Listede eşleşme yok[/yellow]")

        console.print(table)
        if vuln_found:
            console.print(Panel(
                f"[bold red]DİKKAT: {count} adet sürücü adı listede eşleşti; güvenlik açığı doğrulanmadı![/bold red]\n"
                "Hackerlar bu sürücüleri kullanarak antivirüsleri ve Windows korumalarını çekirdek seviyesinde (Kernel) kapatabilir.",
                title="[bold red]Kernel Güvenlik Uyarısı[/bold red]", border_style="red"
            ))
        else:
            console.print("[bold green]Kısa isim listesinde eşleşme bulunmadı; bu sonuç sürücülerin güvenli olduğunu kanıtlamaz.[/bold green]")

    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            console.print(f"[yellow]Komut hatası: {e.stderr.strip()}[/yellow]")
        console.print(f"[bold red]Sürücü tarama hatası:[/bold red] {e}")


def main():
    display_banner()
    scan_kernel_drivers()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
