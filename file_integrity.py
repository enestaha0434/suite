#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FileIntegrity - Kritik Sistem Dosyası Bütünlük Nöbetçisi (FIM / Tripwire)
Geliştirici: ENESxAİs
System32 kritik sistem dosyalarının SHA-256 hash'lerini izleyerek izinsiz modifikasyonları yakalar.
"""

import os
import sys
import hashlib
import json
import re
import tempfile

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
BASELINE_FILE = "fim_baseline.json"

CRITICAL_FILES = [
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\drivers\etc\hosts"
]


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("Integrity Guard", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Kritik Sistem Dosyası Bütünlük Nöbetçisi (FIM) | ENESxAİs[/dim cyan]\n")


def calc_sha256(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    sha = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return ""


def create_baseline():
    baseline = {path: calc_sha256(path) for path in CRITICAL_FILES}
    missing = [path for path, digest in baseline.items() if not digest]
    if missing:
        console.print('[red]Referans oluşturulmadı; şu dosyalar okunamadı:[/red]')
        for path in missing:
            console.print(path)
        return False
    directory = os.path.dirname(os.path.abspath(BASELINE_FILE))
    fd, tmp = tempfile.mkstemp(prefix='.fim-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, BASELINE_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    console.print(f'{len(baseline)} dosya için referans kaydedildi; mevcut sistemin temiz olduğu doğrulanmadı.')
    console.print(f'Referans SHA-256: {calc_sha256(BASELINE_FILE)}')
    console.print('Bu değeri ayrı ve güvenilir bir yerde saklayın; aynı cihazdaki bir değer saldırgana karşı koruma sağlamaz.')
    return True


def check_integrity(expected_baseline_digest=None):
    if not os.path.exists(BASELINE_FILE):
        console.print('[yellow]Referans bulunamadı. Önce güvenilir bir sistemde referans oluşturun.[/yellow]')
        return False
    try:
        with open(BASELINE_FILE, 'rb') as f:
            baseline_bytes = f.read()
        digest = hashlib.sha256(baseline_bytes).hexdigest()
        if expected_baseline_digest:
            if not re.fullmatch(r'[0-9a-fA-F]{64}', expected_baseline_digest) or digest != expected_baseline_digest.lower():
                raise ValueError('Referans SHA-256 değeri beklenen değerle eşleşmiyor')
        else:
            console.print('[yellow]Harici referans özeti verilmedi; referans dosyasının değiştirilmediği doğrulanmadı.[/yellow]')
        baseline = json.loads(baseline_bytes.decode('utf-8'))
        if (not isinstance(baseline, dict) or set(baseline) != set(CRITICAL_FILES)
                or any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', v) for v in baseline.values())):
            raise ValueError('Referans boş, eksik veya geçersiz')
    except (OSError, ValueError, TypeError) as e:
        console.print(f'[red]Bütünlük doğrulanamadı: {e}[/red]')
        return False
    table = Table(title='Dosya Bütünlük Doğrulama Raporu')
    table.add_column('Kritik Dosya')
    table.add_column('Durum')
    changed = False
    for path in CRITICAL_FILES:
        current = calc_sha256(path)
        if not current:
            status = '[red]Okunamadı veya bulunamadı[/red]'
            changed = True
        elif current.lower() != baseline[path].lower():
            status = '[yellow]Referanstan farklı; güncelleme veya başka bir değişiklik olabilir[/yellow]'
            changed = True
        else:
            status = '[green]Referansla eşleşiyor[/green]'
        table.add_row(os.path.basename(path), status)
    console.print(table)
    if changed:
        console.print('[yellow]Bir veya daha fazla dosya doğrulanamadı ya da değişmiş. Nedeni ayrıca inceleyin.[/yellow]')
    else:
        console.print('Tüm seçili dosyalar referansla eşleşiyor; referansın kendisi güvenilirlik kanıtı değildir.')
    return not changed


def main():
    display_banner()
    table = Table(title="FIM Seçenekleri")
    table.add_column("No", style="bold cyan", width=4)
    table.add_column("İşlem", style="bold white")
    table.add_row("1", "Sistem Dosyası Bütünlüğünü Doğrula (Tara)")
    table.add_row("2", "Yeni Referans Tablosu Oluştur")
    table.add_row("q", "Çıkış")
    console.print(table)

    c = console.input("\n[bold cyan]Seçiminiz: [/bold cyan]").strip()
    if c == "1":
        expected = console.input('Ayrı yerde sakladığınız referans SHA-256 (yoksa boş): ').strip()
        check_integrity(expected or None)
    elif c == "2":
        create_baseline()

    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
