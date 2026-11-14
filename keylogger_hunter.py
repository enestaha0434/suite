#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KeyloggerHunter - Klavye Dinleme & Tuş Casusu Avcısı
Geliştirici: ENESxAİs
Süreç adlarında ve pencere başlıklarında şüpheli kelimeler arar; klavye kancalarını incelemez.
"""

import os
import sys
import subprocess
import csv
import io

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
    banner = pyfiglet.figlet_format("Keylogger Hunt", font="slant")
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[dim red]Windows Klavye Dinleme & Keylogger Casusu Avcısı | ENESxAİs[/dim red]\n")


def scan_keyloggers():
    console.print("[bold yellow]→ Süreç adları ve pencere başlıklarında anahtar kelimeler aranıyor; klavye kancaları incelenmez.[/bold yellow]")

    suspicious_keywords = ["keylog", "logger", "hook", "spy", "keystroke", "klog", "agent", "rat"]
    try:
        res = subprocess.run(["tasklist", "/v", "/fo", "csv"], capture_output=True, text=True, check=True)
        rows = list(csv.reader(io.StringIO(res.stdout)))
        if len(rows) < 2:
            raise ValueError("Süreç verisi boş veya okunamadı")

        table = Table(title="Şüpheli Süreç ve Klavye Dinleme Taraması")
        table.add_column("İşlem Adı", style="bold cyan")
        table.add_column("PID", style="yellow")
        table.add_column("Pencere Başlığı", style="dim")
        table.add_column("Durum", style="bold red")

        found_count = 0
        for parts in rows[1:]:
            if len(parts) >= 8:
                pname = parts[0].replace('"', '')
                pid = parts[1].replace('"', '')
                wtitle = parts[-1].replace('"', '')

                p_lower = pname.lower()
                w_lower = wtitle.lower()

                if any(k in p_lower or k in w_lower for k in suspicious_keywords):
                    table.add_row(pname, pid, wtitle[:30], "[bold red]İSİM EŞLEŞMESİ: İNCELEYİN[/bold red]")
                    found_count += 1

        if found_count > 0:
            console.print(table)
            console.print(f"[bold red]DİKKAT: {found_count} adet şüpheli isim eşleşmesi bulundu; zararlı olduğu doğrulanmadı![/bold red]")
        else:
            console.print("[bold green]Anahtar kelime eşleşmesi bulunamadı; bu sonuç keylogger olmadığını göstermez.[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Tarama Hatası:[/bold red] {e}")


def main():
    display_banner()
    scan_keyloggers()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
