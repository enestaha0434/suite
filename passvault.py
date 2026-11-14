#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PassVault - Çevrimdışı & Kriptografik Kişisel Parola Yöneticisi
Geliştirici: ENESxAİs
Bulutsuz, %100 yerel ve ana parola (Master Password) korumalı şifre kasası.
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import string
import tempfile
import shutil
import hmac
from contextlib import contextmanager
from getpass import getpass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("cryptography eksik: pip install -r requirements.txt")
    sys.exit(1)

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
VAULT_FILE = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "WinSecX", "passvault.enc")


class VaultLockedError(Exception):
    pass


@contextmanager
def vault_lock():
    """Kasa oturumu boyunca başka bir PassVault örneğinin yazmasını engelle."""
    os.makedirs(os.path.dirname(os.path.abspath(VAULT_FILE)), exist_ok=True)
    with open(VAULT_FILE + '.lock', 'a+b') as lock_file:
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b'\0')
            lock_file.flush()
        lock_file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise VaultLockedError('Kasa başka bir PassVault örneğinde açık veya kilitlenemedi.') from e
        try:
            yield
        finally:
            lock_file.seek(0)
            if os.name == 'nt':
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("PassVault", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Çevrimdışı & Yerel Kriptografik Şifre Kasası | ENESxAİs[/dim cyan]\n")


def derive_key(master_password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(master_password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def load_vault(master_password: str) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            stored = json.load(f)
        salt = base64.b64decode(stored["salt"], validate=True)
        if stored.get("version") == 2:
            key = derive_key(master_password, salt)
            plaintext = AESGCM(key).decrypt(base64.b64decode(stored["nonce"], validate=True),
                base64.b64decode(stored["data"], validate=True), b"PassVault-v2")
        elif "version" not in stored:
            # Eski format yalnızca geçiş için okunur; yedek alındıktan sonra dönüştürülür.
            key = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, 100_000)
            if not hmac.compare_digest(hashlib.sha256(key).hexdigest(), stored["verifier"]):
                return None
            raw = base64.b64decode(stored["data"], validate=True)
            plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        else:
            return None
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        if "version" not in stored:
            backup = VAULT_FILE + ".legacy.bak"
            if os.path.exists(backup):
                raise OSError("Eski kasa yedeği zaten var; dönüşüm yapılmadı: " + backup)
            shutil.copy2(VAULT_FILE, backup)
            save_vault(data, master_password)
            console.print("[yellow]Eski kasa AES-GCM formatına taşındı. Eski güvensiz yedek: " + backup + "[/yellow]")
        return data
    except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        return None
    except Exception as e:
        from cryptography.exceptions import InvalidTag
        if isinstance(e, InvalidTag):
            return None
        raise


def save_vault(vault_data: dict, master_password: str):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = derive_key(master_password, salt)
    encrypted = AESGCM(key).encrypt(nonce, json.dumps(vault_data, ensure_ascii=False).encode("utf-8"), b"PassVault-v2")
    stored = {"version": 2, "kdf": "scrypt-n16384-r8-p1", "cipher": "AES-256-GCM",
              "salt": base64.b64encode(salt).decode("ascii"),
              "nonce": base64.b64encode(nonce).decode("ascii"),
              "data": base64.b64encode(encrypted).decode("ascii")}
    directory = os.path.dirname(os.path.abspath(VAULT_FILE))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".passvault-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(stored, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, VAULT_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def generate_strong_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return "".join(secrets.choice(alphabet) for _ in range(length))


def vault_menu(vault_data: dict, master_pwd: str):
    while True:
        display_banner()
        table = Table(title=f"PassVault Kasası ({len(vault_data)} Kayıtlı Hesap)")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("İşlem", style="bold white")
        table.add_column("Detay", style="yellow")

        table.add_row("1", "Kayıtlı Parolaları Listele", "Hesapları göster; seçilen şifreyi aç")
        table.add_row("2", "Yeni Hesap / Parola Ekle", "Güvenli kasaya yeni kayıt")
        table.add_row("3", "Kriptografik Güçlü Şifre Üret", "Rastgele güçlü şifre")
        table.add_row("4", "Hesap Sil", "Kasadan kayıt kaldır")
        table.add_row("q", "Kasayı Kilitle & Çık", "Verileri güvenle kapat")

        console.print(table)
        choice = console.input("\n[bold cyan]Seçiminiz: [/bold cyan]").strip()

        if choice == "1":
            if not vault_data:
                console.print("[yellow]Kasada kayıtlı hesap bulunmuyor.[/yellow]")
            else:
                list_table = Table(title="Kayıtlı Hesaplar")
                list_table.add_column("Platform / Site")
                list_table.add_column("Kullanıcı / E-posta")
                for service, info in vault_data.items():
                    list_table.add_row(service, info.get("user", "-"))
                console.print(list_table)
                selected = console.input("[yellow]Şifresi gösterilecek site (iptal için boş): [/yellow]").strip()
                if selected in vault_data:
                    console.print("[yellow]Ekranda seçilen parola gösteriliyor; çevrenizi kontrol edin.[/yellow]")
                    console.print(vault_data[selected].get('pwd', '-'), markup=False)
                elif selected:
                    console.print('[red]Hesap bulunamadı.[/red]')

        elif choice == "2":
            service = console.input("[yellow]Platform / Site Adı (Örn: Google, GitHub): [/yellow]").strip()
            if not service: continue
            if service in vault_data:
                confirm = console.input('[yellow]Bu isimde kayıt var. Üzerine yazılsın mı? (evet/hayir): [/yellow]').strip().lower()
                if confirm not in ('e', 'evet', 'y', 'yes'):
                    console.print('[yellow]Kayıt değiştirilmedi.[/yellow]')
                    continue
            user = console.input("[yellow]Kullanıcı Adı veya E-posta: [/yellow]").strip()
            pwd = getpass("Parola (Boş bırakırsanız güçlü üretilir): ").strip()
            if not pwd:
                pwd = generate_strong_password(18)
                console.print(f"[bold green]Otomatik Üretilen Güçlü Parola: {pwd}[/bold green]")

            vault_data[service] = {"user": user, "pwd": pwd}
            save_vault(vault_data, master_pwd)
            console.print(f"[bold green]✓ '{service}' hesabı şifrelenerek kaydedildi.[/bold green]")

        elif choice == "3":
            new_p = generate_strong_password(20)
            console.print(Panel(
                f"Kriptografik Güçlü Parola:\n[bold green]{new_p}[/bold green]\n\n"
                f"Uzunluk: 20 Karakter (Büyük/Küçük Harf + Rakam + Sembol)",
                title="[bold green]Parola Üretildi[/bold green]", border_style="green"
            ))

        elif choice == "4":
            service = console.input("[yellow]Silinecek Platform / Hesap Adı: [/yellow]").strip()
            if service in vault_data:
                del vault_data[service]
                save_vault(vault_data, master_pwd)
                console.print(f"[bold red]✓ '{service}' kasadan silindi.[/bold red]")
            else:
                console.print("[red]Hesap bulunamadı.[/red]")

        elif choice.lower() == "q":
            console.print("[bold green]Kasa kilitlendi. Güvende kalın![/bold green]")
            break

        console.input("\n[dim]Devam etmek için Enter'a basın...[/dim]")


def _main_unlocked():
    display_banner()
    console.print(f"Kasa yolu: {VAULT_FILE}")
    if not os.path.exists(VAULT_FILE):
        candidates = []
        for base in (os.getcwd(), os.path.dirname(os.path.abspath(__file__))):
            candidate = os.path.abspath(os.path.join(base, 'passvault.enc'))
            if os.path.exists(candidate) and candidate not in candidates and candidate != os.path.abspath(VAULT_FILE):
                candidates.append(candidate)
        if candidates:
            console.print('[yellow]Eski konumda kasa bulundu. Kaynak dosya korunarak yeni konuma kopyalanabilir:[/yellow]')
            for i, candidate in enumerate(candidates, 1):
                console.print(f'{i}. {candidate}')
            selected = console.input('Taşınacak kasa numarası (yeni kasa için boş): ').strip()
            if selected:
                if not selected.isdigit() or not 1 <= int(selected) <= len(candidates):
                    console.print('[red]Geçersiz seçim; işlem iptal edildi.[/red]')
                    return
                os.makedirs(os.path.dirname(VAULT_FILE), exist_ok=True)
                tmp = None
                try:
                    fd, tmp = tempfile.mkstemp(prefix='.passvault-import-', dir=os.path.dirname(VAULT_FILE))
                    with open(candidates[int(selected)-1], 'rb') as src, os.fdopen(fd, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                        dst.flush()
                        os.fsync(dst.fileno())
                    os.link(tmp, VAULT_FILE)  # Hedef zaten varsa üzerine yazılmaz.
                except OSError as e:
                    console.print(f'[red]Kasa kopyalanamadı: {e}[/red]')
                    return
                finally:
                    if tmp and os.path.exists(tmp):
                        os.unlink(tmp)
    if not os.path.exists(VAULT_FILE):
        console.print(Panel(
            "[bold green]YENİ KASA OLUŞTURULUYOR[/bold green]\n"
            "Lütfen kasanız için güçlü bir [bold yellow]Ana Şifre (Master Password)[/bold yellow] belirleyin.\n"
            "[red]DİKKAT:[/red] Bu şifreyi unutursanız verilerinize HİÇ KİMSE erişemez!",
            title="[bold green]İlk Kurulum[/bold green]", border_style="green"
        ))
        p1 = getpass("Ana Şifre Belirleyin: ").strip()
        p2 = getpass("Ana Şifreyi Tekrar Girin: ").strip()
        if p1 != p2 or len(p1) < 12:
            console.print("[bold red]Şifreler eşleşmedi veya 12 karakterden kısa.[/bold red]")
            input("\nÇıkmak için Enter'a basın...")
            return
        save_vault({}, p1)
        vault_menu({}, p1)
    else:
        pwd = getpass("Kasa Ana Şifrenizi Girin: ").strip()
        vault_data = load_vault(pwd)
        if vault_data is None:
            console.print("[bold red]HATA: Yanlış ana şifre! Kasa açılamadı.[/bold red]")
            input("\nÇıkmak için Enter'a basın...")
            return
        vault_menu(vault_data, pwd)


def main():
    try:
        with vault_lock():
            _main_unlocked()
    except (VaultLockedError, OSError) as e:
        console.print(f'[red]Kasa açılamadı: {e}[/red]')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
