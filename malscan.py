#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MalScan - İndirilenler & Masaüstü Zararlı / Sahte Dosya Avcısı
Geliştirici: ENESxAİs
Çift uzantılı dosyaları (fatura.pdf.exe), gizli scriptleri ve sahte simgeli tuzakları avlar.
"""

import os
import sys

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
    banner = pyfiglet.figlet_format("MalScan", font="slant")
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[dim red]Sinsi Tuzak Dosya, Çift Uzantı & Zararlı Avcısı | ENESxAİs[/dim red]\n")


def scan_target_folder(folder_path: str):
    if not os.path.exists(folder_path):
        console.print(f"[red]Klasör bulunamadı:[/red] {folder_path}")
        return

    console.print(f"[bold yellow]→ {folder_path} taranıyor...[/bold yellow]")

    # Tehlikeli ve şüpheli yapılar
    dangerous_exts = [".exe", ".scr", ".vbs", ".vbe", ".bat", ".cmd", ".pif", ".hta", ".wsf", ".iso"]
    deceptive_patterns = [".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe", ".jpg.exe", ".png.exe", ".zip.exe", ".mp4.exe"]

    suspicious_files = []

    for root, _, files in os.walk(folder_path):
        for f in files:
            f_lower = f.lower()
            f_path = os.path.join(root, f)

            # 1. Çift uzantı kontrolü (fatura.pdf.exe tuzağı)
            if any(f_lower.endswith(pat) for pat in deceptive_patterns):
                suspicious_files.append((f_path, "KRİTİK: Çift Uzantılı Sahte Belge Tuzağı!"))
            # 2. Tehlikeli scriptler
            elif any(f_lower.endswith(ext) for ext in [".vbs", ".vbe", ".wsf", ".hta"]):
                suspicious_files.append((f_path, "Şüpheli Arka Plan Scripti"))
            # 3. İsimde aşırı boşluk olanlar (uzantıyı gizlemek için: fatura.pdf        .exe)
            elif "  " in f and any(f_lower.endswith(ext) for ext in dangerous_exts):
                suspicious_files.append((f_path, "Gizlenmiş Uzantı (Boşluk Tuzağı)"))

    table = Table(title=f"Zararlı Dosya Tarama Raporu - {os.path.basename(folder_path)}")
    table.add_column("Dosya Yolu", style="bold cyan")
    table.add_column("Tehdit Türü", style="bold red")

    for path, reason in suspicious_files:
        table.add_row(path, reason)

    if suspicious_files:
        console.print(table)
        console.print(f"[bold red]DİKKAT: Toplam {len(suspicious_files)} adet şüpheli tuzak dosya tespit edildi![/bold red]")
        console.print("[yellow]Bunlar yalnızca dosya adı eşleşmeleridir; zararlı oldukları doğrulanmadı. Dosyalar otomatik silinmez.[/yellow]")
    else:
        console.print("[bold green]Seçilen dosya adı kalıplarında eşleşme bulunmadı; bu, zararlı bulunmadığını göstermez.[/bold green]")


def main():
    while True:
        display_banner()
        user_home = os.path.expanduser("~")
        downloads = os.path.join(user_home, "Downloads")
        desktop = os.path.join(user_home, "Desktop")

        table = Table(title="MalScan Tarama Seçenekleri")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("Klasör", style="bold white")
        table.add_column("Yol", style="yellow")

        table.add_row("1", "İndirilenler (Downloads) Klasörünü Tara", downloads)
        table.add_row("2", "Masaüstü (Desktop) Klasörünü Tara", desktop)
        table.add_row("3", "Özel Bir Klasör Tara", "Manuel giriş")
        table.add_row("q", "Çıkış", "Uygulamayı Kapat")

        console.print(table)
        choice = console.input("\n[bold red]Seçiminiz: [/bold red]").strip()

        if choice == "1":
            scan_target_folder(downloads)
        elif choice == "2":
            scan_target_folder(desktop)
        elif choice == "3":
            cpath = console.input("[yellow]Klasör yolu: [/yellow]").strip().strip('"')
            if cpath: scan_target_folder(cpath)
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
