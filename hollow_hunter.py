#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HollowHunter - Sistem Süreci Yol Kontrolü
Geliştirici: ENESxAİs
svchost.exe, explorer.exe gibi sahte isimler takınarak System32 dışından çalışan virüsleri avlar.
"""

import os
import sys
import subprocess
import csv
import io
import ntpath

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
    banner = pyfiglet.figlet_format("Hollow Hunt", font="slant")
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[dim red]Sistem Süreci Yol Kontrolü | ENESxAİs[/dim red]\n")


def scan_hollow_processes():
    console.print("[bold yellow]→ Kritik sistem süreçlerinin çalışma yolları (System32 doğrulama) denetleniyor...[/bold yellow]")

    # Yalnızca C:\Windows\System32 altından çalışması ZORUNLU olan kritik Windows süreçleri
    system32_only = ["svchost.exe", "lsass.exe", "services.exe", "smss.exe", "csrss.exe", "winlogon.exe"]

    ps_cmd = "$ErrorActionPreference='Stop'; Get-Process | Select-Object Name, Id, Path | ConvertTo-Csv -NoTypeInformation"
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, check=True)
        rows = list(csv.DictReader(io.StringIO(res.stdout)))
        if not rows or not {'Name', 'Id', 'Path'} <= set(rows[0]):
            raise ValueError("Süreç bilgileri boş veya eksik")
        expected_dir = ntpath.normcase(ntpath.normpath(ntpath.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')))

        table = Table(title="Sistem Süreçleri Doğrulama Taraması")
        table.add_column("Süreç Adı", style="bold cyan")
        table.add_column("PID", style="yellow")
        table.add_column("Çalıştığı Dizin / Yol", style="dim")
        table.add_column("Durum", style="bold")

        hollow_found = False
        for row in rows:
            pname = row.get('Name', '').lower()
            pid = row.get('Id', '')
            path = row.get('Path', '')
            full_pname = f"{pname}.exe" if not pname.endswith('.exe') else pname
            if full_pname in system32_only:
                actual_dir = ntpath.normcase(ntpath.normpath(ntpath.dirname(path))) if path else None
                if actual_dir and actual_dir != expected_dir:
                    table.add_row(full_pname, pid, path, '[yellow]Beklenmeyen yol; inceleyin[/yellow]')
                    hollow_found = True
                elif not path:
                    table.add_row(full_pname, pid, '[Erişilemiyor]', '[yellow]Yol doğrulanamadı[/yellow]')
                else:
                    table.add_row(full_pname, pid, path, '[yellow]Yol eşleşiyor; dijital imza ve bellek doğrulanmadı[/yellow]')

        console.print(table)
        if hollow_found:
            console.print(Panel(
                "[bold red]UYARI: Beklenmeyen sistem süreç yolu bulundu.[/bold red]\n"
                "System32 dışında çalışan svchost.exe veya lsass.exe şüpheli olabilir; process hollowing bu yöntemle tespit edilmez.\n"
                "Sonlandırmadan önce dosya yolunu ve dijital imzayı inceleyin.",
                title="[bold red]Kritik Tehdit Uyarısı[/bold red]", border_style="red"
            ))
        else:
            console.print("[bold green]Kontrol edilen yollarda eşleşme bulunmadı; erişilemeyen süreçler doğrulanamaz ve hollowing tespit edilmez.[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Tarama Hatası:[/bold red] {e}")


def main():
    display_banner()
    scan_hollow_processes()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
