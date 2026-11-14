#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortForwardChecker - Dış Dünyaya Açık mıyım? (CGNAT & Port Güvenlik Testi)
Geliştirici: ENESxAİs
Genel IPv4 ve kullanıcı tarafından sağlanan WAN IPv4 adresini karşılaştırır.
"""

import os
import sys
import socket
import ipaddress

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    import pyfiglet
except ImportError:
    print("[!] Gerekli kütüphaneler eksik: pip install requests rich pyfiglet")
    input("\nÇıkmak için Enter'a basın...")
    sys.exit(1)

console = Console()


def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("PortCheck", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim cyan]Dış Dünyaya Açık mıyım? CGNAT & Port Güvenlik Testi | ENESxAİs[/dim cyan]\n")


def classify_wan(public_ip: str, wan_ip: str) -> str:
    """WAN adresinden yalnızca desteklenen çıkarımları yap."""
    try:
        wan = ipaddress.IPv4Address(wan_ip.strip())
        public = ipaddress.IPv4Address(public_ip.strip())
    except ValueError:
        return "Belirsiz: geçerli IPv4 adresleri gerekli."
    if wan in ipaddress.IPv4Network("100.64.0.0/10"):
        return "WAN adresi CGNAT aralığında; İSS tarafında paylaşımlı adresleme olabilir."
    if wan == public and wan.is_global:
        return "WAN ve görünen genel IPv4 eşleşiyor; bu tek başına portun açık olduğunu göstermez."
    if not wan.is_global or wan != public:
        return "WAN ve genel IP farklı veya WAN özel: üst ağda NAT/proxy/VPN olabilir; CGNAT kesin değil."
    return "Belirsiz."


def check_public_ip_and_ports():
    public_ip = None
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=6)
        response.raise_for_status()
        public_ip = str(ipaddress.IPv4Address(response.json()["ip"]))
    except (requests.RequestException, ValueError, KeyError):
        console.print("[yellow]Genel IPv4 alınamadı; CGNAT hakkında sonuç üretilemiyor.[/yellow]")
        return
    console.print(f"İnternette görünen IPv4: [cyan]{public_ip}[/cyan]")
    console.print("Modem arayüzündeki WAN/İnternet IPv4 adresini girin (bilinmiyorsa boş bırakın).")
    wan_ip = console.input("WAN IPv4: ").strip()
    if wan_ip:
        console.print(classify_wan(public_ip, wan_ip))
    else:
        console.print("[yellow]WAN IP olmadan CGNAT belirlenemez.[/yellow]")
    console.print("[yellow]Dış port testi yapılmadı. Port erişimini farklı bir internet bağlantısından test edin.[/yellow]")


def main():
    display_banner()
    check_public_ip_and_ports()
    console.input("\n[dim]Çıkmak için Enter'a basın...[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
