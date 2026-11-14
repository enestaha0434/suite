#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yerel, açıkça başlatılan TCP/UDP DNS filtreleyicisi; sistem DNS ayarlarını değiştirmez."""
import socketserver
import argparse
import ipaddress
import threading
import struct
import sys

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.opcode
    from rich.console import Console
except ImportError:
    print('Bağımlılıklar eksik: pip install -r requirements.txt')
    sys.exit(1)

console = Console()
# Yalnızca örnekler; kapsamlı bir tehdit listesi değildir.
BLOCKED_DOMAINS = {'ads.google.com', 'telemetry.microsoft.com', 'vortex.data.microsoft.com'}
UPSTREAM = '1.1.1.1'


def is_blocked(name, domains=BLOCKED_DOMAINS):
    name = name.rstrip('.').lower()
    labels = name.split('.')
    return any('.'.join(labels[i:]) in domains for i in range(len(labels)))


def handle_query(packet, upstream=UPSTREAM, domains=None, use_tcp=False):
    """Engellenen adlara NXDOMAIN, diğer sorgulara üst sunucunun yanıtı döner."""
    try:
        query = dns.message.from_wire(packet)
    except Exception:
        return None
    if query.flags & dns.flags.QR:
        return None
    if query.opcode() != dns.opcode.QUERY:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()
    if len(query.question) != 1:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()
    question = query.question[0]
    blocked_domains = BLOCKED_DOMAINS if domains is None else domains
    if is_blocked(question.name.to_text(), blocked_domains):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    try:
        if use_tcp:
            response = dns.query.tcp(query, upstream, timeout=3)
        else:
            response = dns.query.udp(query, upstream, timeout=3, ignore_unexpected=True)
        # CNAME ve DNAME hedefleri ile yanıt bölümündeki adları da kontrol et.
        for rrset in response.answer:
            blocked = is_blocked(rrset.name.to_text(), blocked_domains)
            if rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME, dns.rdatatype.SVCB, dns.rdatatype.HTTPS):
                blocked = blocked or any(is_blocked(record.target.to_text(), blocked_domains) for record in rrset)
            if rrset.rdtype == dns.rdatatype.DNAME and question.name.is_subdomain(rrset.name) and question.name != rrset.name:
                # DNAME, alt alan adının önekini hedefe taşır; ortaya çıkan tam adı da kontrol et.
                prefix = question.name.relativize(rrset.name)
                blocked = blocked or any(is_blocked(prefix.concatenate(record.target).to_text(), blocked_domains) for record in rrset)
            if blocked:
                filtered = dns.message.make_response(query)
                filtered.flags |= dns.flags.RA
                filtered.set_rcode(dns.rcode.NXDOMAIN)
                return filtered.to_wire()
        # UDP yanıtlarını istemcinin EDNS sınırına göre kes; büyük yanıtlar TCP ile tekrar sorgulanır.
        limit = 65535 if use_tcp else max(512, min(query.payload if query.edns >= 0 else 512, 1232))
        return response.to_wire(max_size=limit, prefer_truncation=not use_tcp)
    except (OSError, dns.exception.DNSException):
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        response = handle_query(data, getattr(self.server, "upstream", UPSTREAM), getattr(self.server, "domains", None))
        if response is not None:
            sock.sendto(response, self.client_address)


class LocalDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def receive_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


class DNSTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while True:
                header = receive_exact(self.request, 2)
                if not header:
                    return
                length = struct.unpack('!H', header)[0]
                if length == 0:
                    return
                packet = receive_exact(self.request, length)
                if not packet:
                    return
                response = handle_query(packet, self.server.upstream, self.server.domains, use_tcp=True)
                if response is None or len(response) > 65535:
                    return
                self.request.sendall(struct.pack('!H', len(response)) + response)
        except OSError:
            return


class LocalDNSTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def load_blocklist(path):
    """Alan adı satırlarını veya hosts biçimini kabul eder; IP/localhost kayıtlarını dışlar."""
    result = set()
    with open(path, 'r', encoding='utf-8-sig') as f:
        for line in f:
            fields = line.split('#', 1)[0].strip().split()
            if not fields:
                continue
            if fields[0] in ('0.0.0.0', '127.0.0.1', '::', '::1'):
                fields = fields[1:]
            for raw in fields:
                domain = raw.lower().rstrip('.')
                labels = domain.split('.')
                if (len(domain) <= 253 and len(labels) >= 2 and all(0 < len(label) <= 63
                    and label[0] != '-' and label[-1] != '-'
                    and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label)
                    for label in labels)):
                    result.add(domain)
    if not result:
        raise ValueError('Engelleme listesinde geçerli alan adı bulunamadı')
    return result


def main():
    parser = argparse.ArgumentParser(description='Yerel TCP/UDP DNS filtresi; sistem ayarlarını değiştirmez.')
    parser.add_argument('--port', type=int, default=5353, help='Dinleme portu (varsayılan: 5353; standart DNS için 53)')
    parser.add_argument('--blocklist', help='Alan adı satırları veya hosts biçiminde yerel liste')
    parser.add_argument('--upstream', default=UPSTREAM, help='Üst DNS IPv4 adresi')
    args = parser.parse_args()
    try:
        if not 1 <= args.port <= 65535:
            raise ValueError('Port 1 ile 65535 arasında olmalı')
        upstream = str(ipaddress.IPv4Address(args.upstream))
        if ipaddress.IPv4Address(upstream).is_loopback:
            raise ValueError('Döngüyü önlemek için üst DNS yerel döngü adresi olamaz')
        domains = load_blocklist(args.blocklist) if args.blocklist else BLOCKED_DOMAINS
    except (OSError, ValueError) as e:
        console.print(f'[red]Yapılandırma hatası: {e}[/red]')
        return
    console.print(f'[yellow]127.0.0.1:{args.port} TCP/UDP; üst DNS {upstream}; {len(domains)} alan adı. Sistem DNS ayarları değiştirilmez. DoH/DoT ve diğer çözümleyiciler filtrelenmez.[/yellow]')
    if not args.blocklist:
        console.print('[yellow]Örnek liste kullanılıyor; kapsamlı engelleme sağlamaz.[/yellow]')
    if console.input('Yerel hizmet başlatılsın mı? (evet/hayir): ').strip().lower() not in ('e', 'evet', 'y', 'yes'):
        return
    try:
        with LocalDNSServer(('127.0.0.1', args.port), DNSHandler) as udp, LocalDNSTCPServer(('127.0.0.1', args.port), DNSTCPHandler) as tcp:
            udp.upstream = tcp.upstream = upstream
            udp.domains = tcp.domains = domains
            thread = threading.Thread(target=tcp.serve_forever, daemon=True)
            thread.start()
            console.print('[green]Yerel TCP/UDP hizmeti başlatıldı; çıkış Ctrl+C.[/green]')
            try:
                udp.serve_forever(poll_interval=0.5)
            finally:
                tcp.shutdown()
                thread.join()
    except KeyboardInterrupt:
        console.print('[yellow]DNS hizmeti durduruldu.[/yellow]')
    except OSError as e:
        console.print(f'[red]DNS hizmeti başlatılamadı: {e}[/red]')


if __name__ == '__main__':
    main()
