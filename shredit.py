#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShredIt - Dosya üzerine yazma ve silme aracı
Geliştirici: ENESxAİs
Dosyaya yazar ve siler; fiziksel silme garantisi vermez.
"""

import os
import sys
import subprocess
import argparse
import random
import string
import time
import stat

# Otomatik Bağımlılık Kurucu
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
    from rich.table import Table
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler (rich, pyfiglet) bu Python ortamında eksik.")
    ans = input("Otomatik olarak şimdi yüklensin mi? (e/h): ").strip().lower()
    if ans in ["e", "evet", "y", "yes", ""]:
        print("Kütüphaneler yükleniyor, lütfen bekleyin...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "pyfiglet"])
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
        from rich.table import Table
        import pyfiglet
    else:
        sys.exit(1)

console = Console()


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("ShredIt", font="slant")
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[dim red]Üzerine Yazma ve Dosya Silme Aracı | ENESxAİs[/dim red]\n")


def reject_link_components(file_path):
    """Yolun tüm bileşenlerinde sembolik bağlantı ve reparse noktalarını reddet."""
    path = os.path.abspath(file_path)
    current = path
    while True:
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError(f'Bağlantı veya reparse noktası desteklenmiyor: {current}')
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return os.lstat(path)


def safe_file_info(file_path):
    info = reject_link_components(file_path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Yalnızca tek bağlantılı normal dosyalar desteklenir')
    return info


def open_target_exclusively(file_path):
    """Windows'ta reparse takibi olmadan ve paylaşım kapalı bir dosya tutamacı aç."""
    if os.name != 'nt':
        return os.open(file_path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    handle = create(os.path.abspath(file_path), 0x80000000 | 0x40000000 | 0x00010000,
                    0, None, 3, 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except Exception:
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(handle)
        raise


def delete_open_windows_file(fd):
    """Açık dosyayı yol üzerinden tekrar çözümlemeden kapanışta silinmek üzere işaretle."""
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    set_info = kernel.SetFileInformationByHandle
    set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    set_info.restype = wintypes.BOOL
    disposition = ctypes.c_ubyte(1)
    if not set_info(msvcrt.get_osfhandle(fd), 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
        raise ctypes.WinError(ctypes.get_last_error())


def shred_file(file_path: str, passes: int = 3) -> bool:
    if passes < 1:
        console.print('[red]Geçiş sayısı en az 1 olmalıdır.[/red]')
        return False
    try:
        initial = safe_file_info(file_path)
        fd = open_target_exclusively(file_path)
        with os.fdopen(fd, 'r+b', buffering=0) as f:
            opened = os.fstat(f.fileno())
            if ((opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
                    or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode)
                    or getattr(opened, 'st_file_attributes', 0) & 0x400):
                raise ValueError('Dosya açılırken değişti; işlem iptal edildi')
            file_size = opened.st_size
            console.print(f'[yellow]Dosya üzerine yazılıyor: {os.path.basename(file_path)} ({file_size:,} bayt)[/yellow]')
            with Progress(SpinnerColumn(), TextColumn('[progress.description]{task.description}'), BarColumn(), TextColumn('[progress.percentage]{task.percentage:>3.0f}%')) as progress:
                task = progress.add_task('Üzerine yazılıyor...', total=passes)
                for number in range(1, passes + 1):
                    f.seek(0)
                    written = 0
                    while written < file_size:
                        size = min(64 * 1024, file_size - written)
                        data = b'\x00' * size if number == 2 else os.urandom(size)
                        actual = f.write(data)
                        if not actual:
                            raise OSError('Dosyaya yazılamadı')
                        written += actual
                    f.flush()
                    os.fsync(f.fileno())
                    progress.update(task, advance=1)
            if os.name != 'nt':
                current = safe_file_info(file_path)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError('Dosya yolu değişti; silme iptal edildi')
            f.truncate(0)
            os.fsync(f.fileno())
            if os.name == 'nt':
                delete_open_windows_file(f.fileno())
        if os.name != 'nt':
            current = safe_file_info(file_path)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('Dosya yolu değişti; silme iptal edildi')
            os.remove(file_path)
        return True
    except (OSError, ValueError) as e:
        console.print(f'[red]Dosya işlemi tamamlanamadı: {e}[/red]')
        return False


def shred_directory(dir_path: str, passes: int = 3):
    if not os.path.isdir(dir_path):
        console.print(f"[bold red]Klasör bulunamadı:[/bold red] {dir_path}")
        return

    try:
        if not stat.S_ISDIR(reject_link_components(dir_path).st_mode):
            raise ValueError('Hedef bir klasör değil')
    except (OSError, ValueError) as e:
        console.print(f'[red]Klasör işlenmedi: {e}[/red]')
        return
    all_files = []
    skipped = []
    for root, dirs, files in os.walk(dir_path, followlinks=False):
        for name in dirs[:]:
            path = os.path.join(root, name)
            try:
                reject_link_components(path)
            except (OSError, ValueError):
                dirs.remove(name)
                skipped.append(path)
        for f in files:
            all_files.append(os.path.join(root, f))
    if skipped:
        console.print(f'[yellow]{len(skipped)} bağlantılı/erişilemeyen klasör atlandı.[/yellow]')

    console.print(f"[bold red]DİKKAT: Klasör içindeki {len(all_files)} dosya tamamen yok edilecek![/bold red]")
    confirm = console.input("[bold red]Klasördeki TÜM dosyaları kalıcı olarak imha etmek istiyor musunuz? (evet/hayir): [/bold red]").strip().lower()
    if confirm not in ["evet", "yes"]:
        console.print("[yellow]İşlem iptal edildi.[/yellow]")
        return

    success_count = 0
    for fpath in all_files:
        if shred_file(fpath, passes=passes):
            success_count += 1

    for root, dirs, _ in os.walk(dir_path, topdown=False):
        for d in dirs:
            try:
                path = os.path.join(root, d)
                reject_link_components(path)
                os.rmdir(path)
            except (OSError, ValueError):
                pass
    try:
        os.rmdir(dir_path)
    except Exception:
        pass

    console.print(Panel(
        f"[bold green]Klasör İmhası Tamamlandı![/bold green]\n"
        f"Toplam {success_count}/{len(all_files)} dosya üzerine yazıldı ve silindi.",
        title="[bold green]İmha Başarılı[/bold green]",
        border_style="green"
    ))


def interactive_mode():
    while True:
        display_banner()
        console.print(Panel(
            "[bold white]ShredIt - Dosya Üzerine Yazma ve Silme[/bold white]\n"
            "[red]UYARI:[/red] Bu araçla silinen dosyalar\n"
            "[bold red]SSD, yedekler ve dosya sistemi nedeniyle kurtarılamama garantisi yoktur![/bold red]",
            title="[bold red]Kalıcı İmha Uyarısı[/bold red]",
            border_style="red"
        ))

        table = Table(title="İmha Seçenekleri")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("İşlem", style="bold white")
        table.add_column("Standart", style="yellow")

        table.add_row("1", "Tek Bir Dosyayı Kalıcı Olarak İmha Et", "3 geçişli üzerine yazma")
        table.add_row("2", "Tüm Bir Klasörü ve İçeriğini İmha Et", "3 geçişli üzerine yazma")
        table.add_row("q", "Çıkış", "Uygulamayı Kapat")
        console.print(table)

        choice = console.input("\n[bold red]Seçiminiz: [/bold red]").strip()

        if choice == "1":
            fpath = console.input("[yellow]İmha edilecek dosya yolu (Sürükleyip bırakabilirsiniz): [/yellow]").strip().strip('"')
            if not fpath:
                continue
            if not os.path.exists(fpath):
                console.print("[bold red]Hata: Belirtilen dosya bulunamadı.[/bold red]")
            else:
                confirm = console.input(f"[bold red]'{os.path.basename(fpath)}' dosyasını kalıcı olarak yok etmek istediğinizden emin misiniz? (evet/hayir): [/bold red]").strip().lower()
                if confirm in ["evet", "yes", "e", "y"]:
                    if shred_file(fpath, passes=3):
                        console.print(Panel(
                            f"[bold green]✓ Dosya Başarıyla İmha Edildi![/bold green]\n"
                            f"Dosyaya rastgele baytlar ve sıfırlar yazıldı ve dosya silindi. Fiziksel silme garantisi yoktur.",
                            title="[bold green]İşlem Tamam[/bold green]", border_style="green"
                        ))
                else:
                    console.print("[yellow]İşlem iptal edildi.[/yellow]")

        elif choice == "2":
            dpath = console.input("[yellow]İmha edilecek klasör yolu: [/yellow]").strip().strip('"')
            if dpath and os.path.exists(dpath):
                shred_directory(dpath, passes=3)
            else:
                console.print("[bold red]Klasör bulunamadı.[/bold red]")

        elif choice.lower() == "q":
            console.print("[bold green]ShredIt kapatıldı. Güvende kalın![/bold green]")
            break
        else:
            console.print("[bold red]Geçersiz seçim.[/bold red]")

        console.input("\n[dim]Devam etmek için Enter'a basın...[/dim]")


def main():
    parser = argparse.ArgumentParser(description="ShredIt - Askeri Standartta Güvenli Dosya İmha Edici")
    parser.add_argument("path", nargs="?", help="İmha edilecek dosya veya klasör yolu")
    parser.add_argument("-p", "--passes", type=int, default=3, help="Ezme geçiş sayısı (Varsayılan: 3)")
    parser.add_argument("-d", "--directory", action="store_true", help="Hedefin bir klasör olduğunu belirtir")
    parser.add_argument("-f", "--force", action="store_true", help="Onay sormadan doğrudan imha et")

    args = parser.parse_args()

    if not args.path:
        interactive_mode()
        return

    target = args.path.strip('"')
    if not os.path.exists(target):
        console.print(f"[bold red]Hata: Hedef bulunamadı:[/bold red] {target}")
        input("\nÇıkmak için Enter'a basın...")
        sys.exit(1)

    if not args.force:
        console.print(f"[bold red]DİKKAT: '{target}' kalıcı olarak silinecektir![/bold red]")
        conf = input("Onaylıyor musunuz? (evet/hayir): ").strip().lower()
        if conf not in ["evet", "yes", "e", "y"]:
            print("İşlem iptal edildi.")
            sys.exit(0)

    if os.path.isdir(target):
        shred_directory(target, passes=args.passes)
    else:
        if shred_file(target, passes=args.passes):
            console.print(f"[bold green]✓ '{os.path.basename(target)}' başarıyla imha edildi.[/bold green]")

    input("\nÇıkmak için Enter'a basın...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]İşlem iptal edildi.[/yellow]")
