#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowUserHunter - Gizli Yönetici & Arka Kapı Hesap Avcısı
Geliştirici: ENESxAİs
Sistemde gizlice oluşturulmuş yerel yöneticileri ve gizli ($ ile biten) hesapları tespit eder.
"""

import os
import sys
import subprocess
import json

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
    banner = pyfiglet.figlet_format("Shadow Users", font="slant")
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[dim red]Windows Gizli Yönetici & Arka Kapı Hesap Avcısı | ENESxAİs[/dim red]\n")


def scan_local_users():
    # SID, yerelleştirilmiş grup adından bağımsızdır. Grup üyeliği doğrudan üyelikle sınırlıdır.
    command = r"""$ErrorActionPreference='Stop'; $users = @(Get-LocalUser | Select-Object Name,SID,Enabled); $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,SID,ObjectClass); @{users=$users; members=$members} | ConvertTo-Json -Depth 4 -Compress"""
    try:
        result = subprocess.run(['powershell', '-NoProfile', '-Command', command], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        users, members = data['users'], data['members']
        member_sids = {str(m.get('SID', {}).get('Value', '') if isinstance(m.get('SID'), dict) else m.get('SID', '')).lower() for m in members}
        table = Table(title='Yerel hesaplar ve doğrudan yönetici üyeliği')
        for col in ('Kullanıcı', 'Etkin', 'Doğrudan yönetici', 'İşaret'):
            table.add_column(col)
        for user in users:
            sid = user.get('SID', '')
            sid = sid.get('Value', '') if isinstance(sid, dict) else str(sid)
            name = user.get('Name', '')
            table.add_row(name, str(user.get('Enabled', '')), 'Evet' if sid.lower() in member_sids else 'Hayır', 'İnceleyin' if name.endswith('$') else '-')
        console.print(table)
        console.print('Bu yalnızca doğrudan üyeleri gösterir; iç içe gruplar ve hesapların güvenilirliği ayrıca incelenmelidir.')
    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            console.print(f"[yellow]Komut hatası: {e.stderr.strip()}[/yellow]")
        console.print(f'[red]Hesap veya grup bilgileri alınamadı; yönetici durumu bilinmiyor: {e}[/red]')


def main():
    display_banner()
    scan_local_users()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
