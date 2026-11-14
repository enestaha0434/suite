#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNSSwitcher - Hızlı & Güvenli DNS Değiştirici
Geliştirici: ENESxAİs
Windows ağ kartının DNS'ini tek tıkla Cloudflare, Quad9 veya AdGuard yapar.
"""

import os
import sys
import subprocess
import json
import ipaddress

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

DNS_PROFILES = {
    "1": ("Cloudflare (Hızlı & Gizli)", "1.1.1.1", "1.0.0.1"),
    "2": ("Quad9 (Zararlı & Phishing Engelleyici)", "9.9.9.9", "149.112.112.112"),
    "3": ("AdGuard DNS (Tüm Cihazda Reklam Engelleyici)", "94.140.14.14", "94.140.15.15"),
    "4": ("Google DNS", "8.8.8.8", "8.8.4.4"),
    "5": ("Otomatik (DHCP / Modem Varsayılanı)", "dhcp", "dhcp")
}


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("DNSSwitcher", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Windows Hızlı & Güvenli DNS Değiştirici | ENESxAİs[/dim cyan]\n")


def get_active_interfaces():
    command = "@((Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object ifIndex,Name)) | ConvertTo-Json -Compress"
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, check=True, timeout=30)
    data = json.loads(result.stdout)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError('Bağdaştırıcı listesi okunamadı')
    return [(int(x['ifIndex']), str(x['Name'])) for x in data]


def parse_addresses(raw):
    value = json.loads(raw) if raw else []
    value = [value] if isinstance(value, str) else value
    if not isinstance(value, list):
        raise ValueError('DNS adresleri okunamadı')
    return [str(ipaddress.IPv4Address(item)) for item in value]


def apply_dns(index, addresses=None):
    if addresses is None:
        command = f"$ErrorActionPreference='Stop'; Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4 | Set-DnsClientServerAddress -ResetServerAddresses"
    else:
        safe_addresses = [str(ipaddress.IPv4Address(item)) for item in addresses]
        if not safe_addresses:
            raise ValueError('Sabit DNS listesi boş olamaz')
        values = ','.join("'" + item + "'" for item in safe_addresses)
        command = f"$ErrorActionPreference='Stop'; Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses @({values})"
    return subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, check=True, timeout=30)


def restore_dns(index, previous_mode, previous_addresses):
    """Kullanıcının belirttiği eski modu uygular; komut başarısı durumu doğrulamaz."""
    apply_dns(index, None if previous_mode == 'dhcp' else previous_addresses)


def rollback_after_failure(index, mode, addresses, previous):
    if not mode:
        console.print(f'[yellow]Geri alma modu seçilmedi. Önceki adresler: {previous}[/yellow]')
        return
    try:
        restore_dns(index, mode, addresses)
        query = f"(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4).ServerAddresses | ConvertTo-Json -Compress"
        actual = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', query], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        observed = parse_addresses(actual)
        if mode == 'static' and observed != addresses:
            raise ValueError(f'Geri alma sonrası adresler eşleşmiyor: {actual}')
        console.print(f'[yellow]Geri alma komutu tamamlandı; görünen adresler: {actual or "yok"}. Otomatik/elle modunu Windows ayarlarında ayrıca doğrulayın.[/yellow]')
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        console.print(f'[red]Geri alma başarısız: {e}. Önceki adresler: {previous}[/red]')


def set_dns(profile_key: str):
    if profile_key not in DNS_PROFILES:
        console.print('[red]Geçersiz profil.[/red]')
        return
    try:
        adapters = get_active_interfaces()
        if not adapters:
            console.print('[yellow]Etkin ağ bağdaştırıcısı bulunamadı.[/yellow]')
            return
        for i, (index, name) in enumerate(adapters, 1):
            console.print(f'{i}. {name} (arayüz {index})')
        choice = console.input('Bağdaştırıcı numarası (iptal için boş): ').strip()
        if not choice:
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(adapters):
            console.print('[red]Geçersiz bağdaştırıcı.[/red]')
            return
        index, adapter = adapters[int(choice)-1]
        name, primary, secondary = DNS_PROFILES[profile_key]
        query = f"(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4).ServerAddresses | ConvertTo-Json -Compress"
        previous = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', query], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        old_addresses = parse_addresses(previous)
        console.print(f'Bağdaştırıcı: {adapter}; önceki IPv4 DNS adresleri: {previous or "yok"}.')
        console.print('[yellow]Otomatik geri alma için önceki DNS modunu seçin; yanlış seçim bağlantıyı etkileyebilir.[/yellow]')
        mode = console.input('Önceki mod: 1=Otomatik DHCP, 2=Elle DNS, boş=iptal: ').strip()
        if not mode:
            console.print('[yellow]Önceki DNS modu bilinmiyor; hiçbir ayar değiştirilmedi.[/yellow]')
            return
        if mode not in ('1', '2') or (mode == '2' and not old_addresses):
            console.print('[red]Önceki mod veya adresler geçersiz; işlem iptal edildi.[/red]')
            return
        previous_mode = {'1': 'dhcp', '2': 'static'}.get(mode)
        if console.input(f'{name} uygulansın mı? (evet/hayir): ').strip().lower() not in ('e','evet','y','yes'):
            return
        try:
            apply_dns(index, None if primary == 'dhcp' else [primary, secondary])
        except (subprocess.SubprocessError, OSError) as e:
            console.print(f'[red]DNS işlemi başarısız; ayarlar kısmen değişmiş olabilir: {e}[/red]')
            rollback_after_failure(index, previous_mode, old_addresses, previous)
            return
        try:
            actual = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', query], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
            addresses = parse_addresses(actual)
            if primary != 'dhcp' and addresses != [primary, secondary]:
                console.print(f'[yellow]Komut tamamlandı fakat beklenen adresler doğrulanamadı: {actual}. Önceki: {previous}[/yellow]')
                rollback_after_failure(index, previous_mode, old_addresses, previous)
                return
            console.print(f'[green]İşlem tamamlandı; görünen IPv4 DNS: {actual or "yok"}. DHCP modu ayrıca doğrulanmadı.[/green]')
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            console.print(f'[yellow]İşlem tamamlandı ancak sonuç okunamadı: {e}. Önceki: {previous}[/yellow]')
            rollback_after_failure(index, previous_mode, old_addresses, previous)
            return
        try:
            subprocess.run(['ipconfig','/flushdns'], capture_output=True, text=True, check=True, timeout=30)
        except (subprocess.SubprocessError, OSError) as e:
            console.print(f'[yellow]DNS değişti ancak önbellek temizlenemedi: {e}[/yellow]')
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as e:
        console.print(f'[red]DNS değişikliği başlatılamadı: {e}[/red]')


def main():
    while True:
        display_banner()

        table = Table(title="Güvenli DNS Profilleri")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("DNS Sağlayıcı", style="bold white")
        table.add_column("Birincil IP", style="green")
        table.add_column("İkincil IP", style="dim")

        for k, (name, p, s) in DNS_PROFILES.items():
            table.add_row(k, name, p, s)

        table.add_row("q", "Çıkış", "Uygulamayı Kapat", "")
        console.print(table)

        choice = console.input("\n[bold cyan]Seçiminiz: [/bold cyan]").strip()
        if choice in DNS_PROFILES:
            set_dns(choice)
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
