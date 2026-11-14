#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Forensix - Hızlı Olay Müdahale & Adli Bilişim Triage Aracı
Geliştirici: ENESxAİs
Virüs/saldırı şüphesinde sistem delillerini, RAM/süreç durumunu ve logları ZIP paketi olarak toplar.
"""

import os
import sys
import subprocess
import time
import zipfile
import json
import winreg
from datetime import datetime, timedelta

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler eksik: pip install rich pyfiglet")
    input("\nÇıkmak için Enter'a basın...")
    sys.exit(1)

console = Console()


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("Forensix", font="slant")
    console.print(f"[bold magenta]{banner}[/bold magenta]")
    console.print("[dim magenta]Hızlı Olay Müdahale & Dijital Delil Toplayıcı (Triage) | ENESxAİs[/dim magenta]\n")


def collect_evidence():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    triage_dir = f"triage_{timestamp}"
    os.makedirs(triage_dir, exist_ok=False)
    results = {}
    commands = [
        ("processes.csv", ["tasklist", "/v", "/fo", "csv"]),
        ("network_connections.txt", ["netstat", "-ano"]),
        ("dns_cache.txt", ["ipconfig", "/displaydns"]),
        ("scheduled_tasks.csv", ["schtasks", "/query", "/fo", "csv", "/v"]),
        ("system_info.txt", ["systeminfo"]),
    ]
    for filename, command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
            with open(os.path.join(triage_dir, filename), 'w', encoding='utf-8') as f:
                f.write(result.stdout)
            results[filename] = {'status': 'ok'}
        except (OSError, subprocess.SubprocessError) as exc:
            results[filename] = {'status': 'failed', 'error': str(exc)}
    try:
        devices = []
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\USBSTOR') as key:
            count = winreg.QueryInfoKey(key)[0]
            for index in range(count):
                devices.append(winreg.EnumKey(key, index))
        with open(os.path.join(triage_dir, 'usb_history.txt'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(devices))
        results['usb_history.txt'] = {'status': 'ok'}
    except OSError as exc:
        results['usb_history.txt'] = {'status': 'failed', 'error': str(exc)}
    with open(os.path.join(triage_dir, 'collection_status.json'), 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    zip_filename = f"forensics_triage_{timestamp}.zip"
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in os.listdir(triage_dir):
            archive.write(os.path.join(triage_dir, name), arcname=name)
    failed = [name for name, item in results.items() if item['status'] != 'ok']
    console.print(f"Paket: {zip_filename}; başarılı: {len(results) - len(failed)}/{len(results)}")
    if failed:
        console.print(f"[yellow]Eksik veriler: {', '.join(failed)}. Ayrıntılar collection_status.json içinde.[/yellow]")
    else:
        console.print('Tüm toplama komutları tamamlandı; içeriklerin kapsamını ayrıca doğrulayın.')
    return results


def main():
    display_banner()
    console.print("Bu araç virüs veya saldırı anında sistemin anlık adli delillerini tek bir ZIP dosyasına toplar.\n")
    confirm = console.input("[bold magenta]Delil toplama işlemini başlatmak istiyor musunuz? (evet/hayir): [/bold magenta]").strip().lower()
    if confirm in ["evet", "yes", "e", "y"]:
        collect_evidence()
    else:
        console.print("[yellow]İşlem iptal edildi.[/yellow]")

    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
