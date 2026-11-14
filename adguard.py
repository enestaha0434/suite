#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Hosts - Sistem Genelinde Reklam & Casus Domain Engelleyici
Geliştirici: ENESxAİs
Tarayıcı, uygulama ve oyunlardaki reklamları/telemetriyi hosts dosyası üzerinden engeller.
"""

import os
import sys
import shutil
import subprocess
import tempfile
from datetime import datetime

try:
    import requests
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler eksik: pip install requests rich pyfiglet")
    input("\nÇıkmak için Enter'a basın...")
    sys.exit(1)

console = Console()
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP_PATH = r"C:\Windows\System32\drivers\etc\hosts.winsecx_backup"

# Yaygın reklam ve casus yazılım engelleme listesi URL'si
BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("AdGuard Host", font="slant")
    console.print(f"[bold green]{banner}[/bold green]")
    console.print("[dim green]Sistem Genelinde Reklam & Casusluk Engelleyici | ENESxAİs[/dim green]\n")


def is_admin():
    """Yönetici (Admin) yetkisi kontrolü."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


BEGIN = b"# BEGIN WINSECX MANAGED HOSTS"
END = b"# END WINSECX MANAGED HOSTS"


def strip_managed_block(data: bytes) -> bytes:
    """Yalnızca işaretlenmiş bloğu kaldır; bozuk işaretlerde dosyaya dokunma."""
    if data.count(BEGIN) != data.count(END) or data.count(BEGIN) > 1:
        raise ValueError("Hosts dosyasındaki WinSecX işaretleri bozuk; dosya değiştirilmedi.")
    if BEGIN not in data:
        return data
    start, end = data.index(BEGIN), data.index(END)
    if end < start:
        raise ValueError("Hosts işaretlerinin sırası bozuk; dosya değiştirilmedi.")
    end += len(END)
    if data[end:end + 2] == b"\r\n":
        end += 2
    elif data[end:end + 1] == b"\n":
        end += 1
    return data[:start] + data[end:]


def replace_hosts_safely(original: bytes, content: bytes):
    """Aynı dizinde yazıp doğrula; Windows'ta özgün dosya ACL bilgisini koru."""
    directory = os.path.dirname(os.path.abspath(HOSTS_PATH))
    fd, tmp = tempfile.mkstemp(prefix='.winsecx-hosts-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        with open(tmp, 'rb') as f:
            if f.read() != content:
                raise OSError('Geçici hosts dosyası doğrulanamadı')
        with open(HOSTS_PATH, 'rb') as f:
            if f.read() != original:
                raise OSError('Hosts dosyası işlem sırasında değişti; işlem iptal edildi')
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            replace = kernel.ReplaceFileW
            replace.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
            replace.restype = wintypes.BOOL
            if not replace(os.path.abspath(HOSTS_PATH), tmp, None, 0, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(tmp, HOSTS_PATH)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def enable_adblock():
    if not is_admin():
        console.print("[red]Yönetici yetkisi gerekli.[/red]")
        return
    try:
        res = requests.get(BLOCKLIST_URL, timeout=15)
        res.raise_for_status()
        entries = []
        for line in res.text.splitlines():
            fields = line.split('#', 1)[0].split()
            if len(fields) == 2 and fields[0] in ('0.0.0.0', '127.0.0.1'):
                domain = fields[1].lower().rstrip('.')
                if domain != 'localhost' and len(domain) <= 253 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in domain) and '.' in domain:
                    entries.append('0.0.0.0 ' + domain)
        if not entries:
            raise ValueError("İndirilen listede geçerli engelleme kaydı bulunamadı.")
        with open(HOSTS_PATH, 'rb') as f:
            current = f.read()
        base = strip_managed_block(current)
        if not os.path.exists(BACKUP_PATH):
            shutil.copy2(HOSTS_PATH, BACKUP_PATH)
        separator = b'' if not base or base.endswith(b'\n') else b'\r\n'
        block = BEGIN + b'\r\n' + ('\r\n'.join(entries)).encode('ascii') + b'\r\n' + END + b'\r\n'
        replace_hosts_safely(current, base + separator + block)
        console.print(f"[green]Hosts bloğu güncellendi: {len(entries)} kayıt. Diğer kayıtlar korundu.[/green]")
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, text=True, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            console.print(f"[yellow]Hosts güncellendi; DNS önbelleği temizlenemedi: {exc}[/yellow]")
    except Exception as exc:
        console.print(f"[red]Hosts güncelleme hatası: {exc}[/red]")


def disable_adblock():
    if not is_admin():
        console.print("[red]Yönetici yetkisi gerekli.[/red]")
        return
    try:
        with open(HOSTS_PATH, 'rb') as f:
            current = f.read()
        result = strip_managed_block(current)
        if result == current:
            console.print("[yellow]Yönetilen blok bulunamadı; dosya değiştirilmedi. Eski sürüm yedeğini gerekirse elle inceleyin.[/yellow]")
            return
        replace_hosts_safely(current, result)
        console.print("[green]Yalnızca WinSecX bloğu kaldırıldı; diğer kayıtlar korundu.[/green]")
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, text=True, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            console.print(f"[yellow]Blok kaldırıldı; DNS önbelleği temizlenemedi: {exc}[/yellow]")
    except Exception as exc:
        console.print(f"[red]Hosts güncelleme hatası: {exc}[/red]")


def main():
    while True:
        display_banner()
        table = Table(title="AdGuard Hosts Yönetimi")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("İşlem", style="bold white")
        table.add_column("Açıklama", style="yellow")

        table.add_row("1", "Reklam & Casus Korumasını Aç", "İndirilen listeyi yönetilen bloğa ekler")
        table.add_row("2", "WinSecX Bloğunu Kaldır", "Diğer hosts kayıtlarını korur")
        table.add_row("q", "Çıkış", "Uygulamayı Kapat")

        console.print(table)
        choice = console.input("\n[bold green]Seçiminiz: [/bold green]").strip()

        if choice == "1":
            enable_adblock()
        elif choice == "2":
            disable_adblock()
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
