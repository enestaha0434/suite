#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysHardening - Windows Savunma Kalkanı & Zafiyet Kapatıcı
Geliştirici: ENESxAİs
SMBv1, LLMNR/NetBIOS, AutoPlay ve tehlikeli Windows kapılarını tek tıkla kilitler.
"""

import os
import sys
import subprocess
import winreg

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
    banner = pyfiglet.figlet_format("SysHardening", font="slant")
    console.print(f"[bold blue]{banner}[/bold blue]")
    console.print("[dim blue]Windows Zafiyet Kapatıcı & Sistem Sıkılaştırma Kalkanı | ENESxAİs[/dim blue]\n")


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def apply_hardening():
    if not is_admin():
        console.print(Panel(
            "[bold red]YÖNETİCİ YETKİSİ GEREKLİ![/bold red]\n"
            "Sistem zafiyetlerini kapatmak için bu programı lütfen\n"
            "[bold yellow]'Yönetici Olarak Çalıştır'[/bold yellow] ile açın.",
            title="[bold red]Erişim Engellendi[/bold red]", border_style="red"
        ))
        return

    console.print("[bold yellow]→ Windows güvenlik sıkılaştırma kuralları uygulanıyor...[/bold yellow]\n")

    actions = [
        # 1. SMBv1 Protokolünü Kapat (WannaCry fidye virüsünü engeller)
        ("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart", "SMBv1 Fidye Virüsü Protokolü Kapatıldı"),
        # 2. USB AutoPlay / AutoRun Devre Dışı Bırak (USB virüslerini engeller)
        ('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f', "USB AutoPlay / Otomatik Çalıştırma Kapatıldı"),
        # 3. LLMNR Zehirlenmesini Kapat (Yerel ağ şifre hırsızlığını engeller)
        ('reg add "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f', "LLMNR Ağ Zehirlenmesi Kapatıldı"),
        # 4. Uzak Masaüstü NLA Zorunluluğu Getir
        ('reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f', "RDP NLA Ağ Seviyesinde Kimlik Doğrulama Açıldı")
    ]

    table = Table(title="Uygulanan Güvenlik Kalkanı")
    table.add_column("Güvenlik Önlemi", style="bold green")
    table.add_column("Durum", style="cyan")

    for cmd, desc in actions:
        try:
            if "Disable-WindowsOptionalFeature" in cmd:
                subprocess.run(["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; " + cmd], capture_output=True, text=True, check=True)
            else:
                subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
            table.add_row(desc, "[yellow]Komut tamamlandı; ayar ve yeniden başlatma durumu ayrıca doğrulanmalı[/yellow]")
        except subprocess.CalledProcessError as e:
            table.add_row(desc, f"[red]Başarısız (kod {e.returncode}): {(e.stderr or e.stdout or '').strip()}[/red]")
        except Exception as e:
            table.add_row(desc, f"[red]Hata: {e}[/red]")

    console.print(table)
    console.print(Panel(
        "İşlemler tamamlandı; her sonucun yukarıdaki durumunu kontrol edin. "
        "Bazı değişiklikler yeniden başlatma gerektirebilir.",
        title="İşlem sonuçları", border_style="yellow"
    ))


def main():
    display_banner()
    console.print("Bu araç Windows'un fabrikasyon açık gelen ve hackerların en çok kullandığı arka kapılarını kilitler.\n")
    conf = console.input("[bold blue]Güvenlik sıkılaştırma kalkanını devreye almak istiyor musunuz? (evet/hayir): [/bold blue]").strip().lower()
    if conf in ["evet", "yes", "e", "y"]:
        apply_hardening()
    else:
        console.print("[yellow]İşlem iptal edildi.[/yellow]")

    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
