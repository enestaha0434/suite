#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LeakWatch - Açıkta Bırakılmış Hassas Veri & Secrets Avcısı
Geliştirici: ENESxAİs
Metin ve kod dosyalarındaki unutulmuş API key, kredi kartı ve şifreleri tarar.
"""

import os
import sys
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

PATTERNS = {
    "Kredi Kartı": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Generic API Key / Token": re.compile(r"(?i)(api[_-]?key|secret|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
    "Private Key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Şifre Tanımı (Hardcoded)": re.compile(r"(?i)(password|parola|passwd)[\s:=]+['\"]([^'\"]{6,})['\"]")
}


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("LeakWatch", font="slant")
    console.print(f"[bold magenta]{banner}[/bold magenta]")
    console.print("[dim magenta]Unutulmuş Hassas Veri, API Key & Şifre Avcısı | ENESxAİs[/dim magenta]\n")


def scan_directory_for_leaks(target_dir: str):
    if not os.path.isdir(target_dir):
        console.print('[red]Hedef dizin bulunamadı.[/red]')
        return None
    findings, errors = [], []
    extensions = ('.txt', '.log', '.env', '.json', '.xml', '.yaml', '.yml', '.ini', '.conf', '.py', '.js', '.html', '.php', '.sh')
    scanned = 0
    def on_walk_error(error):
        errors.append((getattr(error, 'filename', None) or target_dir, str(error)))
    for root, _, files in os.walk(target_dir, onerror=on_walk_error):
        for name in files:
            if not (name.lower().endswith(extensions) or name.startswith('.env')):
                continue
            path = os.path.join(root, name)
            try:
                # Eksik/bozuk UTF-8 göz ardı edilmez; kısmi tarama olarak raporlanır.
                with open(path, 'r', encoding='utf-8') as f:
                    for line_no, line in enumerate(f, 1):
                        for label, regex in PATTERNS.items():
                            if regex.search(line):
                                findings.append((path, line_no, label))
                scanned += 1
            except (OSError, UnicodeError) as e:
                errors.append((path, str(e)))
    table = Table(title=f'Potansiyel eşleşmeler ({len(findings)})')
    for column in ('Dosya', 'Satır', 'Tür', 'Değer'):
        table.add_column(column)
    for path, line, label in findings[:40]:
        table.add_row(path, str(line), label, '[MASKELENDİ]')
    console.print(table)
    console.print(f'{scanned} dosya tarandı; {len(findings)} olası eşleşme, {len(errors)} okuma hatası.')
    if errors:
        console.print('[yellow]Tarama eksik; okunamayan yerler:[/yellow]')
        for path, error in errors[:40]:
            console.print(f'{path}: {error}')
    if not findings:
        console.print('[yellow]Seçili kurallarda eşleşme bulunmadı; bu sonuç gizli veri olmadığını kanıtlamaz.[/yellow]')
    return {'scanned': scanned, 'findings': len(findings), 'errors': len(errors)}


def main():
    while True:
        display_banner()
        table = Table(title="LeakWatch Tarama Seçenekleri")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("Hedef", style="bold white")
        table.add_column("Açıklama", style="yellow")

        table.add_row("1", "Masaüstünü Tara", "Masaüstündeki notlar ve dosyalar")
        table.add_row("2", "Belgelerim Klasörünü Tara", "Belgeler altındaki metinler")
        table.add_row("3", "Özel Klasör / Proje Dizini Tara", "Belirttiğiniz bir kod/klasör yolu")
        table.add_row("q", "Çıkış", "Uygulamayı Kapat")

        console.print(table)
        choice = console.input("\n[bold magenta]Seçiminiz: [/bold magenta]").strip()

        user_home = os.path.expanduser("~")
        if choice == "1":
            scan_directory_for_leaks(os.path.join(user_home, "Desktop"))
        elif choice == "2":
            scan_directory_for_leaks(os.path.join(user_home, "Documents"))
        elif choice == "3":
            cpath = console.input("[yellow]Klasör Yolu: [/yellow]").strip().strip('"')
            if cpath: scan_directory_for_leaks(cpath)
        elif choice.lower() == "q":
            break
        else:
            console.print("[red]Geçersiz seçim.[/red]")

        console.input("\n[dim]Devam etmek için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
