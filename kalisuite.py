#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinSecX / KaliLiteX Security Tools
Geliştirici: ENESxAİs
Halk İçin Açık Kaynak Kişisel Savunma, Tehdit Avcısı, Honeypot ve Ağ Kalkanı
"""

import os
import sys
import subprocess
import socket
import ssl
import time
import json
import hashlib
import html
import re
import winreg
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple

# Temel kütüphaneler
try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler eksik. Lütfen çalıştırın: pip install -r requirements.txt")
    sys.exit(1)

console = Console()
ETHICAL_USAGE_AGREED = False


# ==========================================
# GÜVENLİK SÖZLEŞMESİ & BANNER
# ==========================================
def check_ethical_usage():
    global ETHICAL_USAGE_AGREED
    if not ETHICAL_USAGE_AGREED:
        console.print(Panel(
            "[bold cyan]WinSecX - Kişisel Güvenlik Denetim Araçları[/bold cyan]\n"
            "[green]Misyon: Güvenlik ve mahremiyet herkesin temel hakkıdır.[/green]\n"
            "[bold yellow]UYARI:[/bold yellow] Yalnızca kendi cihazlarınızda ve izinli test ortamlarında kullanınız.",
            title="[bold green]Hoş Geldiniz[/bold green]",
            border_style="cyan"
        ))
        agree = console.input("[bold yellow]Kullanım şartlarını kabul ediyor musunuz? (e/h): [/bold yellow]").strip().lower()
        if agree in ["e", "evet", "y", "yes"]:
            ETHICAL_USAGE_AGREED = True
        else:
            console.print("[bold red]Program sonlandırıldı.[/bold red]")
            sys.exit(0)


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("WinSecX NextGen", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Windows Güvenlik Denetimi ve Ağ Araçları | ENESxAİs[/dim cyan]\n")


def save_html_report(title: str, data: Dict):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)
    filename = os.path.join("reports", f"report_{timestamp}.html")

    rows_html = ""
    for k, v in data.items():
        val_clean = html.escape(str(v)).replace("\n", "<br>")
        k = html.escape(str(k))
        rows_html += f"""
        <tr>
            <td style="font-weight:600; color:#58a6ff; width:30%; vertical-align:top;">{k}</td>
            <td style="color:#c9d1d9; font-family:monospace; white-space:pre-wrap;">{val_clean}</td>
        </tr>
        """

    title = html.escape(str(title))
    report_html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>WinSecX Raporu - {title}</title>
    <style>
        body {{ background:#0d1117; color:#c9d1d9; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; margin:30px; }}
        .box {{ max-width:900px; margin:0 auto; background:#161b22; border:1px solid #30363d; border-radius:8px; padding:25px; }}
        h1 {{ color:#58a6ff; margin-top:0; border-bottom:1px solid #30363d; padding-bottom:10px; }}
        .badge {{ background:#1f6feb; color:#fff; padding:4px 10px; border-radius:4px; font-size:12px; }}
        table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
        th, td {{ border:1px solid #30363d; padding:10px; text-align:left; }}
        th {{ background:#21262d; color:#8b949e; }}
        tr:nth-child(even) {{ background:#1a1f26; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>🛡️ WinSecX Analiz Raporu</h1>
        <p><span class="badge">{title}</span> &nbsp;&bull;&nbsp; Tarih: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <table>
            <thead><tr><th>Parametre / Test</th><th>Sonuç / Değer</th></tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
</body>
</html>"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_html)
    console.print(f"[bold green]✓ Rapor kaydedildi:[/bold green] [cyan]{filename}[/cyan]")


def get_local_ip_and_gateway():
    local_ip = "127.0.0.1"
    gateway = "192.168.1.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    try:
        res = subprocess.run(["ipconfig"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            if "Default Gateway" in line or "Varsayılan Ağ Geçidi" in line:
                parts = line.split(":")
                if len(parts) > 1 and parts[1].strip() and "." in parts[1]:
                    gateway = parts[1].strip()
                    break
    except Exception:
        pass

    return local_ip, gateway


def run_interactive_tool(cmd_list: List[str], tool_name: str):
    console.print(f"[bold yellow]→ {tool_name} çalıştırılıyor...[/bold yellow]")
    try:
        subprocess.run(cmd_list, check=False)
    except FileNotFoundError:
        console.print(f"[bold red]Hata: '{cmd_list[0]}' sistemi üzerinde kurulu bulunamadı.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Hata:[/bold red] {e}")


# ==========================================
# 1. 🪤 HONEYPOT & CANARY FİDYE KORUMASI
# ==========================================
def run_personal_honeypot(port: int = 8080):
    """Kişisel Tuzak: Yerel ağdan bilgisayara sızmaya çalışanları yakalar ve alarm basar."""
    console.print(Panel(
        f"[bold yellow]Kişisel Honeypot (Sazan Tuzağı) Aktif![/bold yellow]\n"
        f"Dinlenen Port: [bold cyan]{port}[/bold cyan]\n"
        f"Ağınızdaki herhangi bir cihaz veya saldırgan bu porta eriştiği anda alarm verilecek.\n"
        f"[dim]Durdurmak için CTRL+C tuşlarına basabilirsiniz.[/dim]",
        title="[bold red]Honeypot Devrede[/bold red]",
        border_style="yellow"
    ))
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
    except Exception as e:
        console.print(f"[bold red]Port dinleme hatası (Port dolu olabilir):[/bold red] {e}")
        return

    try:
        while True:
            try:
                client_sock, client_addr = server.accept()
                intruder_ip, intruder_port = client_addr
                console.print(Panel(
                    f"[bold red]🚨 ALARM: AĞDAN BİRİ BİLGİSAYARINIZA BAĞLANDI![/bold red]\n\n"
                    f"Saldırgan/Cihaz IP: [bold yellow]{intruder_ip}[/bold yellow]\n"
                    f"Kaynak Port: [cyan]{intruder_port}[/cyan]\n"
                    f"Zaman: {datetime.now().strftime('%H:%M:%S')}\n"
                    f"[dim]Bağlantı sahte yanıt verilip sonlandırıldı.[/dim]",
                    title="[bold red]Saldırı / Port Tarama Tespiti[/bold red]",
                    border_style="red"
                ))
                try:
                    client_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nWinSecX Honeypot: Connection Logged.")
                except Exception:
                    pass
                client_sock.close()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        console.print("\n[yellow]Honeypot nöbeti durduruldu.[/yellow]")
    finally:
        server.close()


def canary_fingerprint(path):
    """Dosyanın içeriğini ve boyutunu oku; erişim hataları çağırana bildirilir."""
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def get_desktop_directory():
    """Yönlendirilmiş Windows masaüstünü kullanıcı kayıtlarından bul."""
    try:
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _ = winreg.QueryValueEx(key, 'Desktop')
        path = os.path.expandvars(value)
        if os.path.isdir(path):
            return path
    except OSError:
        pass
    return os.path.join(os.path.expanduser('~'), 'Desktop')


def ransomware_canary_guard():
    """Örnek yem dosyasını süreç çalıştığı sürece izler; saldırıyı durdurmaz."""
    desktop = get_desktop_directory()
    if not os.path.isdir(desktop):
        console.print('[red]Masaüstü bulunamadı; izleme başlatılmadı.[/red]')
        return
    path = os.path.join(desktop, '!winsecx_canary_trap.txt')
    try:
        try:
            with open(path, 'x', encoding='utf-8') as f:
                f.write('WinSecX uyarı dosyası. Bu dosya güvenlik izleme için kullanılır.\n')
        except FileExistsError:
            console.print('[yellow]Mevcut yem dosyası kullanılacak; başlangıçtaki içeriği doğrulanmaz.[/yellow]')
        baseline = canary_fingerprint(path)
        console.print(f'[yellow]Yem dosyası izleniyor: {path}\nProgram açık kaldığı sürece 2 saniyede bir kontrol edilir; zararlıyı durdurmaz. Çıkış: Ctrl+C[/yellow]')
        while True:
            time.sleep(2)
            try:
                current = canary_fingerprint(path)
            except OSError as e:
                console.print(f'[bold red]UYARI: Yem dosyası silindi veya okunamıyor: {e}[/bold red]')
                return
            if current != baseline:
                console.print('[bold red]UYARI: Yem dosyasının içeriği değişti. Nedeni araştırın; bu tek başına fidye yazılımı kanıtı değildir.[/bold red]')
                return
    except KeyboardInterrupt:
        console.print('[yellow]Yem dosyası izleme durduruldu.[/yellow]')
    except OSError as e:
        console.print(f'[red]İzleme başlatılamadı: {e}[/red]')


# ==========================================
# 2. 👁️ KAMERA, MİKROFON & PANO (CLIPPER) AVCISI
# ==========================================
def check_camera_mic_spyware():
    """Windows Registry'den kamera ve mikrofonu arka planda kullanan uygulamaları tespit eder."""
    console.print("[bold yellow]→ Arka planda Kamera ve Mikrofon erişimi denetleniyor...[/bold yellow]")
    report = {}

    table = Table(title="Kamera & Mikrofon Erişim Geçmişi ve Aktiflik")
    table.add_column("Donanım", style="cyan", width=12)
    table.add_column("Uygulama / Paket Adı", style="bold white")
    table.add_column("Son Erişim Durumu", style="green")

    devices = [("webcam", "Kamera"), ("microphone", "Mikrofon")]
    found_any = False

    for dev_key, dev_label in devices:
        reg_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{dev_key}"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
            idx = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(key, idx)
                    sub_key = winreg.OpenKey(key, sub_name, 0, winreg.KEY_READ)
                    try:
                        # LastUsedTimeStop 0 ise şu an erişiliyor olabilir!
                        stop_time, _ = winreg.QueryValueEx(sub_key, "LastUsedTimeStop")
                        start_time, _ = winreg.QueryValueEx(sub_key, "LastUsedTimeStart")
                        status = "[bold red]ŞU AN AKTİF VEYA YENİ KULLANILDI![/bold red]" if stop_time == 0 and start_time > 0 else "Geçmişte Kullanıldı"
                        table.add_row(dev_label, sub_name, status)
                        report[f"{dev_label}: {sub_name}"] = status
                        found_any = True
                    except Exception:
                        pass
                    winreg.CloseKey(sub_key)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    if found_any:
        console.print(table)
    else:
        console.print("[green]Kamera veya mikrofona şüpheli aktif erişim tespit edilemedi.[/green]")

    save_html_report("Kamera ve Mikrofon Denetimi", report)


def clipboard_clipper_hunter():
    """Kripto cüzdan adreslerini çalan Pano (Clipboard Clipper) virüsünü denetler."""
    console.print("[bold yellow]→ Pano Kripto Hırsızı (Clipboard Clipper) denetleniyor...[/bold yellow]")
    try:
        res = subprocess.run(["powershell", "-Command", "Get-Clipboard"], capture_output=True, text=True)
        content = res.stdout.strip()
        console.print(f"[dim]Şu anki Pano İçeriği: {content[:40]}...[/dim]")

        # Kripto cüzdan regex benzeri yapılar
        crypto_detected = False
        if len(content) in [34, 42, 44] and (content.startswith("1") or content.startswith("3") or content.startswith("bc1") or content.startswith("0x") or content.startswith("T")):
            crypto_detected = True

        if crypto_detected:
            console.print("[bold yellow]DİKKAT: Panonuzda bir kripto para cüzdan adresi tespit edildi.[/bold yellow]")
            console.print("[cyan]Öneri: Bir yere yapıştırırken adresin değişip değişmediğini mutlaka gözle doğrulayın![/cyan]")
        else:
            console.print("[bold green]✓ Panonuzda şüpheli bir kripto adresi veya manipülasyon tespit edilmedi.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Pano denetim hatası:[/bold red] {e}")


# ==========================================
# 3. 🌐 PHISHING LINK, VIRUSTOTAL & E-POSTA
# ==========================================
def check_suspicious_url(url: str):
    """URLhaus API ile linkin zararlı veya phishing olup olmadığını sorgular."""
    console.print(f"[bold yellow]→ {url} URLhaus küresel tehdit veritabanında sorgulanıyor...[/bold yellow]")
    api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        res = requests.post(api_endpoint, data={"url": url}, timeout=8)
        if res.status_code == 200:
            data = res.json()
            status = data.get("query_status", "unknown")
            if status == "ok":
                threat = data.get("threat", "Bilinmeyen Tehdit")
                url_status = data.get("url_status", "Bilinmiyor")
                console.print(Panel(
                    f"[bold red]DİKKAT: BU LİNK TEHDİT VERİTABANINDA BULUNDU![/bold red]\n\n"
                    f"Tehdit Türü: [bold yellow]{threat}[/bold yellow]\n"
                    f"Durum: {url_status}\n"
                    f"[red]ÖNERİ:[/red] Bu linke kesinlikle tıklamayın, açmayın!",
                    title="[bold red]Tehdit Tespit Edildi[/bold red]", border_style="red"
                ))
            elif status == "no_results":
                console.print(Panel(
                    "[bold green]Bu sorguda kayıt bulunamadı veya sorgu tamamlanamadı; linkin güvenliği doğrulanmadı.[/bold green]\n"
                    "[dim]Not: Yepyeni bir phishing sitesi olabileceğini unutmayın, yine de dikkatli olun.[/dim]",
                    title="[bold green]Sorgu Sonucu[/bold green]", border_style="green"
                ))
            else:
                console.print(f"[yellow]Sorgu tamamlanamadı: {status}[/yellow]")
        else:
            console.print("[red]API yanıt vermedi.[/red]")
    except Exception as e:
        console.print(f"[bold red]Sorgu Hatası:[/bold red] {e}")


def virustotal_hash_lookup(file_or_hash: str):
    """Dosyanın SHA-256 hash'ini hesaplar ve VirusTotal rapor linkini/durumunu döker."""
    if os.path.exists(file_or_hash):
        console.print(f"[yellow]Dosya hash'i hesaplanıyor: {file_or_hash}...[/yellow]")
        sha256 = hashlib.sha256()
        with open(file_or_hash, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        f_hash = sha256.hexdigest()
    else:
        f_hash = file_or_hash.strip()

    vt_url = f"https://www.virustotal.com/gui/file/{f_hash}"
    console.print(Panel(
        f"Dosya / Hash: [bold cyan]{f_hash}[/bold cyan]\n\n"
        f"VirusTotal Rapor Linki:\n[bold green]{vt_url}[/bold green]\n\n"
        f"[dim]Bu linki tarayıcınızda açarak 70+ antivirüs motorunun sonuçlarını canlı görebilirsiniz.[/dim]",
        title="[bold cyan]VirusTotal İstihbarat[/bold cyan]",
        border_style="cyan"
    ))


def check_email_breach(email: str):
    """HaveIBeenPwned tarzı e-posta sızıntı denetimi."""
    console.print(f"[bold yellow]→ {email} için sızıntı kontrolü bağlantısı hazırlanıyor...[/bold yellow]")
    url = f"https://leak-lookup.com/api/search"
    # Alternatif açık kaynak API
    try:
        console.print(Panel(
            f"E-Posta: [bold cyan]{email}[/bold cyan]\n\n"
            f"Resmi HIBP Arama Linki:\n[bold green]https://haveibeenpwned.com/account/{email}[/bold green]\n\n"
            f"[dim]Gizliliğinizi korumak için resmi web sitesinde kontrol edebilirsiniz.[/dim]",
            title="[bold green]E-Posta Sızıntı Denetimi[/bold green]",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[bold red]Hata:[/bold red] {e}")


# ==========================================
# 4. ⏰ ZAMANLANMIŞ GÖREVLER & PAYLAŞIMLAR
# ==========================================
def audit_scheduled_tasks():
    """Virüslerin gizlice çalıştırdığı şüpheli Windows Zamanlanmış Görevlerini tarar."""
    console.print("[bold yellow]→ Windows Zamanlanmış Görevler (Persistence) taranıyor...[/bold yellow]")
    try:
        res = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True, text=True)
        lines = res.stdout.splitlines()

        table = Table(title="Şüpheli veya Standart Dışı Zamanlanmış Görevler")
        table.add_column("Görev Adı", style="bold cyan")
        table.add_column("Çalıştırılan Komut", style="yellow")

        count = 0
        for line in lines[1:50]:  # İlk 50 görevi filtrele
            if "powershell" in line.lower() or "cmd.exe" in line.lower() or "wscript" in line.lower() or "cscript" in line.lower() or ".vbs" in line.lower():
                parts = line.split('","')
                if len(parts) >= 2:
                    tname = parts[0].replace('"', '')
                    cmd = parts[-1].replace('"', '') if len(parts) > 8 else parts[1]
                    table.add_row(tname, cmd[:60])
                    count += 1

        if count > 0:
            console.print(table)
            console.print(f"[bold red]{count} adet script çalıştıran zamanlanmış görev tespit edildi.[/bold red]")
        else:
            console.print("[bold green]✓ Şüpheli script/powershell çalıştıran zamanlanmış görev tespit edilmedi.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Görev tarama hatası:[/bold red] {e}")


def audit_network_shares():
    """Bilgisayarda ağa açık bırakılmış paylaşılan klasörleri döker."""
    console.print("[bold yellow]→ Bilgisayarda dışa açık paylaşımlar (Network Shares) denetleniyor...[/bold yellow]")
    try:
        res = subprocess.run(["net", "share"], capture_output=True, text=True)
        table = Table(title="Açık Ağ Paylaşımları")
        table.add_column("Paylaşım Adı", style="bold cyan")
        table.add_column("Yerel Klasör Yolu", style="green")

        has_custom_share = False
        for line in res.stdout.splitlines():
            if "$" not in line and (":\\" in line or len(line.split()) >= 2):
                parts = line.split()
                if len(parts) >= 2 and not line.startswith("Share name") and not line.startswith("---") and not line.startswith("Paylaşım"):
                    sname, spath = parts[0], parts[1]
                    table.add_row(sname, spath)
                    has_custom_share = True

        console.print(table)
        if has_custom_share:
            console.print("[bold red]UYARI:[/bold red] Yerel ağdaki herkese açık bırakılmış özel klasörleriniz var!")
        else:
            console.print("[green]✓ Sadece standart Windows gizli yönetim paylaşımları (C$, ADMIN$) mevcut.[/green]")
    except Exception as e:
        console.print(f"[bold red]Paylaşım denetim hatası:[/bold red] {e}")


def audit_browser_extensions():
    """Chrome ve Edge tarayıcılarındaki uzantıları ve olası çerez hırsızlarını listeler."""
    console.print("[bold yellow]→ Chrome & Edge tarayıcı eklentileri (Extensions) taranıyor...[/bold yellow]")
    user_home = os.path.expanduser("~")
    ext_paths = [
        ("Chrome", os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Default\Extensions")),
        ("Edge", os.path.join(user_home, r"AppData\Local\Microsoft\Edge\User Data\Default\Extensions"))
    ]

    table = Table(title="Yüklü Tarayıcı Eklentileri")
    table.add_column("Tarayıcı", style="cyan")
    table.add_column("Eklenti ID", style="yellow")
    table.add_column("Eklenti Adı", style="bold green")

    found_count = 0
    for bname, bpath in ext_paths:
        if os.path.exists(bpath):
            try:
                for eid in os.listdir(bpath):
                    e_sub = os.path.join(bpath, eid)
                    if os.path.isdir(e_sub):
                        name = eid
                        # manifest'ten adı çekmeye çalış
                        try:
                            v_dir = os.listdir(e_sub)[0]
                            manifest = os.path.join(e_sub, v_dir, "manifest.json")
                            if os.path.exists(manifest):
                                with open(manifest, "r", encoding="utf-8", errors="ignore") as mf:
                                    m_data = json.load(mf)
                                    name = m_data.get("name", eid)
                        except Exception:
                            pass
                        table.add_row(bname, eid[:16] + "...", str(name))
                        found_count += 1
            except Exception:
                pass

    if found_count > 0:
        console.print(table)
        console.print(f"[dim]Toplam {found_count} eklenti bulundu. Tanımadığınız eklentileri tarayıcı ayarlarından kaldırın.[/dim]")
    else:
        console.print("[green]Tarayıcı eklenti klasörleri bulunamadı veya eklenti yüklü değil.[/green]")


def dns_leak_and_doh_test():
    """DNS sızıntısı ve şifreli DNS (DoH) durumunu test eder."""
    console.print("[bold yellow]→ DNS sunucuları listeleniyor; sızıntı ve şifreleme test edilmez.[/bold yellow]")
    try:
        res = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
        dns_servers = []
        for line in res.stdout.splitlines():
            if "DNS Servers" in line or "DNS Sunucuları" in line:
                parts = line.split(":")
                if len(parts) > 1 and parts[1].strip():
                    dns_servers.append(parts[1].strip())

        table = Table(title="Aktif DNS Sunucuları")
        table.add_column("DNS Sunucu IP", style="bold cyan")
        table.add_column("Güvenlik Durumu", style="bold")

        known_secure = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]
        for dns in dns_servers:
            if dns in known_secure:
                table.add_row(dns, "[green]Bilinen sağlayıcı (şifreleme doğrulanmadı)[/green]")
            elif dns.startswith("192.168.") or dns.startswith("10."):
                table.add_row(dns, "[yellow]Modem / Yerel Ağ DNS[/yellow]")
            else:
                table.add_row(dns, "[dim]Özel DNS Sunucusu[/dim]")

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]DNS test hatası:[/bold red] {e}")


# ==========================================
# 5. DİĞER MODÜLLER (ÖNCEKİLER)
# ==========================================
def scan_persistence_and_spyware():
    """Virüslerin açılışa eklediği Registry Run anahtarlarını, Startup'ı ve Hosts dosyasını denetler."""
    console.print("[bold yellow]→ Casus yazılım ve başlangıç kalıcılık noktaları taranıyor...[/bold yellow]")
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run")
    ]
    table = Table(title="Windows Başlangıç (Kayıt Defteri) Programları")
    table.add_column("Konum", style="dim")
    table.add_column("İsim", style="bold cyan")
    table.add_column("Komut", style="yellow")
    for hkey, subkey, label in reg_paths:
        try:
            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, idx)
                    table.add_row(label, name, str(val))
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
    console.print(table)


def parse_arp_table(output):
    """Arp çıktısındaki arayüz/IP çiftlerini MAC adreslerine eşle."""
    current_interface = None
    entries = {}
    for line in output.splitlines():
        match = re.search(r'(?i)(?:interface|arayüz|arabirim)\s*:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            current_interface = match.group(1)
            continue
        match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+', line)
        if current_interface and match:
            ip, mac = match.groups()
            entries[(current_interface, ip)] = mac.lower().replace(':', '-')
    return entries


def arp_changes(previous, current):
    return [(key, previous[key], value) for key, value in current.items()
            if key in previous and previous[key] != value]


def detect_arp_spoofing():
    console.print('[yellow]ARP kayıtları 5 saniyede bir karşılaştırılır. MAC değişimi saldırı kanıtı değildir; çıkış Ctrl+C.[/yellow]')
    previous = None
    try:
        while True:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
            current = parse_arp_table(result.stdout)
            if not current:
                console.print('[yellow]ARP kaydı okunamadı; karşılaştırma yapılamıyor.[/yellow]')
            elif previous is None:
                console.print(f'{len(current)} ARP kaydı başlangıç referansı olarak alındı.')
                previous = current
            else:
                for (interface, ip), old, new in arp_changes(previous, current):
                    console.print(f'[bold yellow]ARP değişimi: arayüz {interface}, IP {ip}: {old} → {new}. Manuel inceleyin.[/bold yellow]')
                # Kaybolan kayıtları koru; geri geldiklerinde de değişim incelenir.
                previous.update(current)
            time.sleep(5)
    except KeyboardInterrupt:
        console.print('[yellow]ARP izleme durduruldu.[/yellow]')
    except (OSError, subprocess.CalledProcessError) as e:
        console.print(f'[red]ARP izleme başarısız: {e}[/red]')


def clean_usb_drive(drive_letter: str):
    """Sürücü kökündeki gizli/sistem dosyalarını listeler; öznitelikleri değiştirmez."""
    drive_letter = drive_letter.strip().rstrip('\\/:')
    if len(drive_letter) != 1 or not drive_letter.isascii() or not drive_letter.isalpha():
        console.print('[red]Tek bir sürücü harfi girin.[/red]')
        return
    drive = drive_letter.upper() + ':\\'
    try:
        entries = []
        with os.scandir(drive) as iterator:
            for item in iterator:
                try:
                    flags = getattr(item.stat(follow_symlinks=False), 'st_file_attributes', 0)
                    if flags & 0x6:
                        entries.append(item.name)
                except OSError as e:
                    console.print(f'[yellow]Okunamadı: {item.name}: {e}[/yellow]')
        for name in entries:
            console.print(name)
        console.print(f'{len(entries)} gizli veya sistem girdisi bulundu. Yalnızca sürücü kökü listelendi; dosyalar değiştirilmedi.')
    except OSError as e:
        console.print(f'[red]Sürücü okunamadı: {e}[/red]')


def check_pwned_password(password: str):
    """HaveIBeenPwned API ile şifre sorgusu."""
    if not password: return
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"User-Agent": "WinSecX", "Add-Padding": "true"}, timeout=8)
        res.raise_for_status()
        if not res.text.strip() or any(len(line.split(':')) != 2 or len(line.split(':')[0]) != 35 or not all(c in '0123456789ABCDEF' for c in line.split(':')[0].upper()) or not line.split(':')[1].strip().isdigit() for line in res.text.splitlines() if line.strip()):
            raise ValueError("Sızıntı servisi geçersiz yanıt verdi")
        count = 0
        for h in res.text.splitlines():
            if h.split(":")[0].strip() == suffix:
                count = int(h.split(":")[1].strip())
                break
        if count > 0:
            console.print(f"[bold red]BU ŞİFRE DAHA ÖNCE {count:,} KEZ SIZDIRILMIŞ![/bold red]")
        else:
            console.print("[bold green]Bu sorguda parola eşleşmesi bulunamadı; güvenli olduğu garanti edilmez.[/bold green]")
    except Exception as e:
        console.print(f"[red]Hata:[/red] {e}")


def pc_security_health_check():
    local_ip, gateway = get_local_ip_and_gateway()
    console.print(f"[bold yellow]→ PC Güvenlik Denetimi ({local_ip})...[/bold yellow]")
    table = Table(title="Kişisel PC Güvenliği")
    table.add_column("Parametre", style="cyan")
    table.add_column("Durum", style="bold")
    for p, name in [(445, "SMB Port 445 (Fidye Riski)"), (3389, "RDP Port 3389 (Uzak Masaüstü)")]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            open_p = (s.connect_ex((local_ip, p)) == 0)
            s.close()
            status = "[bold red]AÇIK (RİSK)![/bold red]" if open_p else "[green]Kapalı (Güvenli)[/green]"
            table.add_row(name, status)
        except Exception:
            pass
    console.print(table)


def gateway_router_audit():
    _, gateway = get_local_ip_and_gateway()
    console.print(f"[bold yellow]→ Modem Güvenlik Denetimi ({gateway})...[/bold yellow]")
    table = Table(title=f"Modem / Router ({gateway})")
    table.add_column("Port", style="cyan")
    table.add_column("Durum", style="bold")
    for p, name in [(21, "FTP"), (23, "Telnet (Şifresiz)"), (80, "HTTP Panel"), (443, "HTTPS Panel")]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            open_p = (s.connect_ex((gateway, p)) == 0)
            s.close()
            status = "[bold red]AÇIK[/bold red]" if open_p else "[green]Kapalı[/green]"
            table.add_row(f"{name} ({p})", status)
        except Exception:
            pass
    console.print(table)


def scan_local_network_devices():
    local_ip, _ = get_local_ip_and_gateway()
    subnet = ".".join(local_ip.split(".")[:3]) + "."
    console.print(f"[bold yellow]→ Yerel Ağ ({subnet}1-254) cihazları aranıyor...[/bold yellow]")
    found = []
    def p_check(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            if s.connect_ex((ip, 80)) == 0 or s.connect_ex((ip, 445)) == 0 or s.connect_ex((ip, 53)) == 0:
                found.append(ip)
            s.close()
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(p_check, [f"{subnet}{i}" for i in range(1, 255)])
    table = Table(title=f"Seçili TCP portlarında yanıt veren IP adresleri ({len(found)})")
    table.add_column("IP Adresi", style="bold green")
    for ip in sorted(found): table.add_row(ip)
    console.print(table)


def check_listening_ports():
    console.print("[bold yellow]→ Dinlenen Portlar taranıyor...[/bold yellow]")
    res = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True)
    table = Table(title="Dinlenen Portlar (LISTENING)")
    table.add_column("Adres", style="cyan")
    table.add_column("PID", style="yellow")
    for line in res.stdout.splitlines():
        if "LISTENING" in line:
            parts = line.split()
            if len(parts) >= 4:
                table.add_row(parts[1], parts[-1])
    console.print(table)


def fast_port_scanner(target: str, prange: str = "1-1024"):
    console.print(f"[bold yellow]→ {target} taranıyor ({prange})...[/bold yellow]")
    sp, ep = [int(x) for x in prange.split("-")]
    open_p = []
    def sp_check(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((target, p)) == 0: open_p.append(p)
            s.close()
        except Exception: pass
    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(sp_check, range(sp, ep + 1))
    table = Table(title=f"Açık Portlar ({len(open_p)})")
    table.add_column("Port", style="green")
    for p in sorted(open_p): table.add_row(str(p))
    console.print(table)


def scan_wifi_networks():
    console.print("[bold yellow]→ Wi-Fi taranıyor...[/bold yellow]")
    res = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
    if res.returncode != 0:
        console.print("[yellow]Wi-Fi servisi aktif değil veya kablosuz adaptör bulunamadı.[/yellow]")
        return
    console.print(res.stdout[:500] + "...")


def list_saved_wifi_keys():
    console.print("[bold yellow]→ Kayıtlı Wi-Fi şifreleri alınıyor...[/bold yellow]")
    res = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True)
    for line in res.stdout.splitlines():
        if "All User Profile" in line or "Tüm Kullanıcı Profili" in line:
            p = line.split(":", 1)[1].strip()
            k_res = subprocess.run(["netsh", "wlan", "show", "profile", f"name={p}", "key=clear"], capture_output=True, text=True)
            pwd = "[Parola Yok]"
            for kl in k_res.stdout.splitlines():
                if "Key Content" in kl or "Anahtar İçeriği" in kl:
                    pwd = kl.split(":", 1)[1].strip()
            console.print(f"[cyan]{p}[/cyan] -> [bold green]{pwd}[/bold green]")


def audit_web_security(url: str):
    if not url.startswith("http"): url = "https://" + url
    console.print(f"[bold yellow]→ {url} Güvenlik Başlıkları...[/bold yellow]")
    try:
        response = requests.get(url, timeout=6)
        response.raise_for_status()
        h = response.headers
        for k in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]:
            st = "[green]MEVCUT[/green]" if k in h else "[red]EKSİK[/red]"
            console.print(f"{k}: {st}")
    except Exception as e: console.print(f"[red]Hata:[/red] {e}")


def crtsh_subdomain_finder(domain: str):
    console.print(f"[bold yellow]→ {domain} Subdomain araması...[/bold yellow]")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        subs = set(x['name_value'] for x in r.json())
        console.print(f"[green]Bulunan subdomainler: {len(subs)} adet.[/green]")
        for s in list(subs)[:20]: console.print(f"- {s}")
    except Exception as e: console.print(f"[red]Hata:[/red] {e}")


def calculate_file_hash(filepath: str):
    if not os.path.exists(filepath): return
    m, s = hashlib.md5(), hashlib.sha256()
    with open(filepath, "rb") as f:
        while c := f.read(8192): m.update(c); s.update(c)
    console.print(f"MD5: [cyan]{m.hexdigest()}[/cyan]\nSHA256: [green]{s.hexdigest()}[/green]")


# ==========================================
# ANA KONTROL MENÜSÜ (NEXT-GEN EDR SUITE)
# ==========================================
def main_menu():
    check_ethical_usage()
    while True:
        display_banner()
        table = Table(title="WinSecX Güvenlik Denetim Araçları", border_style="cyan")
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("Kategori", style="yellow", width=18)
        table.add_column("Modül / İşlem", style="bold white")
        table.add_column("Özellik / Savunma", style="green", width=16)

        # 1. Tehdit Avcısı & Tuzaklar (YENİ)
        table.add_row("1", "Tuzak & Alarm", "Kişisel Honeypot (Ağ Saldırı Tuzağı)", "[bold red]Ağ Alarmı[/bold red]")
        table.add_row("2", "Dosya Kontrolü", "Yem dosyası değişim izleyicisi", "[bold red]Ransomware[/bold red]")
        table.add_row("3", "Tehdit Avcısı", "Kamera ve Mikrofon Erişim Kayıtları", "[bold magenta]Spyware Cam/Mic[/bold magenta]")
        table.add_row("4", "Tehdit Avcısı", "Panoda Kripto Adresi Kontrolü", "[bold yellow]Clipboard Safe[/bold yellow]")
        table.add_row("5", "İstihbarat", "Şüpheli Link / Phishing Dedektörü (URLhaus)", "[bold red]Phishing Guard[/bold red]")
        table.add_row("6", "İstihbarat", "VirusTotal Dosya / Hash Rapor Bağlantısı", "[bold cyan]70+ AV Motoru[/bold cyan]")
        table.add_row("7", "İstihbarat", "E-posta Sızıntı Kontrol Bağlantısı", "[bold cyan]Data Breach[/bold cyan]")

        # 2. Sistem & Kalıcılık Avcıları
        table.add_row("8", "Kalıcılık", "Registry Başlangıç Kayıtları", "Persistence")
        table.add_row("9", "Kalıcılık", "Zamanlanmış Görevler (Scheduled Tasks)", "Task Scheduler")
        table.add_row("10", "Ağ Koruması", "ARP MAC Değişim İzleyicisi", "Değişim alarmı")
        table.add_row("11", "Zararlı Temizlik", "USB Kökünde Gizli/Sistem Girdilerini Listele", "Salt okunur")
        table.add_row("12", "Sistem Denetim", "Açık Klasör & Ağ Paylaşımı (Net Share)", "Share Audit")
        table.add_row("13", "Gizlilik & Ağ", "Yapılandırılmış DNS Sunucularını Listele", "DNS envanteri")
        table.add_row("14", "Gizlilik & Web", "Tarayıcı Eklentilerini Listele", "Stealer Audit")

        # 3. PC, Ağ & Port Güvenliği
        table.add_row("15", "PC Güvenlik", "Yerel SMB ve RDP Port Kontrolü", "Hardening")
        table.add_row("16", "Modem Güvenlik", "Modem / Router Açık Taraması (Telnet/FTP)", "Gateway Audit")
        table.add_row("17", "Ağ Taraması", "/24 Ağda 80, 445 ve 53 TCP Portlarını Tara", "Cihaz Tespiti")
        table.add_row("18", "Sistem & Port", "Windows Dinlenen Portlar & PID", "Netstat")
        table.add_row("19", "Port Taraması", "Hızlı Soket Port Tarayıcısı", "Port Scan")

        # 4. Wi-Fi & Bütünlük
        table.add_row("20", "Kablosuz Ağ", "Çevredeki Wi-Fi Ağlarını Tara", "Netsh Wi-Fi")
        table.add_row("21", "Kablosuz Ağ", "Kayıtlı Wi-Fi Parolalarını Listele", "Netsh Profil")
        table.add_row("22", "Bütünlük & Hash", "Dosya MD5 ve SHA256 Hash Hesaplayıcı", "Hashlib")

        # 5. Web, OSINT & Pentest
        table.add_row("23", "Web Güvenlik", "HTTP Güvenlik Başlıkları", "Web Audit")
        table.add_row("24", "OSINT", "crt.sh ile Subdomain Keşfi (Ücretsiz)", "REST API")
        table.add_row("25", "Kimlik Güvenlik", "Güvenli Şifre Sızıntı Kontrolü (HIBP)", "k-Anonymity")
        table.add_row("26", "Pentest CLI", "Nmap Port & Servis Taraması", "CLI / Nmap")
        table.add_row("27", "Pentest CLI", "SQLMap SQL Injection Testi (--batch)", "CLI / SQLMap")
        table.add_row("28", "Dosya İmhası", "ShredIt Dosya Üzerine Yazma ve Silme", "[bold red]Silme[/bold red]")

        # Bağımsız Mini-Uygulamalar
        table.add_row("29", "Ağ Radarı", "NetGuard Canlı Ağ & Şüpheli Bağlantı İzleyici", "TCP izleme")
        table.add_row("30", "Reklam/Casus", "AdGuard Hosts Sistem Genelinde Engelleyici", "Hosts listesi")
        table.add_row("31", "Adli Bilişim", "Forensix Olay Müdahale & Delil Toplayıcı", "[bold magenta]Triage ZIP[/bold magenta]")
        table.add_row("32", "Parola Kasası", "PassVault Çevrimdışı & Güvenli Şifre Yöneticisi", "[bold yellow]Kriptografik[/bold yellow]")

        table.add_row("33", "Bağımsız araç", "MalScan", "malscan.py")
        table.add_row("34", "Bağımsız araç", "Sertifika kontrolü", "cert_guard.py")
        table.add_row("35", "Bağımsız araç", "DNS değiştirici", "dns_switcher.py")
        table.add_row("36", "Bağımsız araç", "Sızıntı taraması", "leak_watch.py")
        table.add_row("37", "Bağımsız araç", "Sistem sıkılaştırma", "sys_hardening.py")
        table.add_row("38", "Bağımsız araç", "Süreç adı taraması", "keylogger_hunter.py")
        table.add_row("39", "Bağımsız araç", "Genel IP ve WAN kontrolü", "port_forward_checker.py")
        table.add_row("40", "Bağımsız araç", "Wi-Fi ağları", "eviltwin_radar.py")
        table.add_row("41", "Bağımsız araç", "Güvenlik duvarı", "firewall_auditor.py")
        table.add_row("42", "Bağımsız araç", "Yerel hesaplar", "shadow_user_hunter.py")
        table.add_row("43", "Bağımsız araç", "Süreç yolu kontrolü", "hollow_hunter.py")
        table.add_row("44", "Bağımsız araç", "Dosya bütünlüğü", "file_integrity.py")
        table.add_row("45", "Bağımsız araç", "DNS Sinkhole (yerel TCP/UDP)", "dns_sinkhole.py")
        table.add_row("46", "Bağımsız araç", "Sürücü denetimi", "byovd_auditor.py")

        table.add_row("q", "Çıkış", "Güvenli Çıkış Yap", "[red]Kapat[/red]")

        console.print(table)
        choice = console.input("\n[bold cyan]Seçiminiz: [/bold cyan]").strip()

        # Yeni Nesil Modüller
        if choice == "1":
            port_input = console.input("[yellow]Honeypot Portu (Varsayılan 8080): [/yellow]").strip() or "8080"
            run_personal_honeypot(int(port_input))
        elif choice == "2":
            ransomware_canary_guard()
        elif choice == "3":
            check_camera_mic_spyware()
        elif choice == "4":
            clipboard_clipper_hunter()
        elif choice == "5":
            url_in = console.input("[yellow]Test edilecek şüpheli link (URL): [/yellow]").strip()
            if url_in: check_suspicious_url(url_in)
        elif choice == "6":
            f_in = console.input("[yellow]Dosya Yolu veya SHA-256 Hash: [/yellow]").strip().strip('"')
            if f_in: virustotal_hash_lookup(f_in)
        elif choice == "7":
            email_in = console.input("[yellow]Kontrol edilecek e-posta adresi: [/yellow]").strip()
            if email_in: check_email_breach(email_in)
        elif choice == "8":
            scan_persistence_and_spyware()
        elif choice == "9":
            audit_scheduled_tasks()
        elif choice == "10":
            detect_arp_spoofing()
        elif choice == "11":
            dletter = console.input("[yellow]USB Sürücü Harfi (Örn: E): [/yellow]").strip()
            if dletter: clean_usb_drive(dletter)
        elif choice == "12":
            audit_network_shares()
        elif choice == "13":
            dns_leak_and_doh_test()
        elif choice == "14":
            audit_browser_extensions()
        elif choice == "15":
            pc_security_health_check()
        elif choice == "16":
            gateway_router_audit()
        elif choice == "17":
            scan_local_network_devices()
        elif choice == "18":
            check_listening_ports()
        elif choice == "19":
            target = console.input("[yellow]Hedef IP / Host: [/yellow]").strip()
            prange = console.input("[yellow]Port Aralığı (Örn: 1-1024): [/yellow]").strip() or "1-1024"
            if target: fast_port_scanner(target, prange)
        elif choice == "20":
            scan_wifi_networks()
        elif choice == "21":
            list_saved_wifi_keys()
        elif choice == "22":
            fpath = console.input("[yellow]Dosya Yolu: [/yellow]").strip().strip('"')
            if fpath: calculate_file_hash(fpath)
        elif choice == "23":
            url = console.input("[yellow]Web Sitesi (Örn: example.com): [/yellow]").strip()
            if url: audit_web_security(url)
        elif choice == "24":
            domain = console.input("[yellow]Hedef Alan Adı: [/yellow]").strip()
            if domain: crtsh_subdomain_finder(domain)
        elif choice == "25":
            pwd = console.input("[yellow]Şifre: [/yellow]").strip()
            if pwd: check_pwned_password(pwd)
        elif choice == "26":
            target = console.input("[yellow]Hedef IP: [/yellow]").strip()
            if target: run_interactive_tool(["nmap", "-sV", target], "Nmap")
        elif choice == "27":
            target = console.input("[yellow]Hedef URL: [/yellow]").strip()
            if target: run_interactive_tool(["sqlmap", "-u", target, "--batch"], "SQLMap")
        elif choice == "28":
            run_interactive_tool([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "shredit.py")], "ShredIt")
        elif choice == "29":
            run_interactive_tool([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard.py")], "NetGuard")
        elif choice == "30":
            run_interactive_tool([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "adguard.py")], "AdGuard Hosts")
        elif choice == "31":
            run_interactive_tool([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensix.py")], "Forensix")
        elif choice == "32":
            run_interactive_tool([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "passvault.py")], "PassVault")
        elif choice in {"33": "malscan.py", "34": "cert_guard.py", "35": "dns_switcher.py", "36": "leak_watch.py", "37": "sys_hardening.py", "38": "keylogger_hunter.py", "39": "port_forward_checker.py", "40": "eviltwin_radar.py", "41": "firewall_auditor.py", "42": "shadow_user_hunter.py", "43": "hollow_hunter.py", "44": "file_integrity.py", "45": "dns_sinkhole.py", "46": "byovd_auditor.py"}:
            standalone = {"33": "malscan.py", "34": "cert_guard.py", "35": "dns_switcher.py", "36": "leak_watch.py", "37": "sys_hardening.py", "38": "keylogger_hunter.py", "39": "port_forward_checker.py", "40": "eviltwin_radar.py", "41": "firewall_auditor.py", "42": "shadow_user_hunter.py", "43": "hollow_hunter.py", "44": "file_integrity.py", "45": "dns_sinkhole.py", "46": "byovd_auditor.py"}[choice]
            run_interactive_tool([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), standalone)], standalone)
        elif choice.lower() == "q":
            console.print("[bold green]WinSecX kapatıldı. Güvende kalın![/bold green]")
            break
        else:
            console.print("[bold red]Geçersiz seçim.[/bold red]")

        console.input("\n[dim]Devam etmek için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[bold red]İşlem iptal edildi.[/bold red]")
