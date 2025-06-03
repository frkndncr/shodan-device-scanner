#!/usr/bin/env python3
"""
Improved Shodan Tool v2.0 - OSS Plan Compatible
Sağlam hata yönetimi ve gelişmiş özelliklerle
"""

import requests
import json
import os
import sys
import argparse
from datetime import datetime
import socket
import re
from urllib.parse import quote
import time
from pathlib import Path

class Colors:
    """Terminal renk kodları"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def get_api_key():
    """API anahtarını al"""
    # 1. Komut satırı argümanı (zaten handle ediliyor)
    # 2. Çevre değişkeni
    api_key = os.getenv('SHODAN_API_KEY')
    if api_key and api_key != "YOUR_SHODAN_API_KEY":
        return api_key
    
    # 3. Config dosyası
    config_file = "config/scanner_config.ini"
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    if line.strip().startswith('shodan_key'):
                        key = line.split('=', 1)[1].strip()
                        if key and key != "YOUR_SHODAN_API_KEY":
                            return key
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Config dosyası okunamadı: {e}{Colors.ENDC}")
    
    # 4. Manuel giriş
    try:
        return input(f"{Colors.CYAN}🔑 Shodan API anahtarınızı girin: {Colors.ENDC}").strip()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}❌ İşlem iptal edildi{Colors.ENDC}")
        sys.exit(1)

def api_request(endpoint, api_key, timeout=20):
    """Sağlam API isteği"""
    base_url = "https://api.shodan.io"
    separator = "&" if "?" in endpoint else "?"
    url = f"{base_url}{endpoint}{separator}key={api_key}"
    
    try:
        response = requests.get(url, timeout=timeout)
        
        # Response içeriğini kontrol et
        if response.status_code == 200:
            try:
                data = response.json()
                return {'success': True, 'data': data, 'status': 200}
            except json.JSONDecodeError:
                return {'success': False, 'error': 'Invalid JSON response', 'status': 200}
        else:
            # Hata response'unu parse et
            try:
                error_data = response.json()
                error_msg = error_data.get('error', f'HTTP {response.status_code}')
            except:
                error_msg = f'HTTP {response.status_code}'
            
            return {
                'success': False, 
                'status': response.status_code, 
                'error': error_msg,
                'raw_response': response.text[:200]
            }
            
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Request timeout', 'status': 'timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Connection error', 'status': 'connection_error'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'status': 'unknown_error'}

class ShodanOSSTool:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ShodanOSSTool/2.0'})
        
        # API key'i test et
        if not self._test_api_key():
            print(f"{Colors.RED}❌ API anahtarı geçersiz veya erişim yok{Colors.ENDC}")
            sys.exit(1)
    
    def _test_api_key(self):
        """API anahtarını test et"""
        result = api_request('/api-info', self.api_key, timeout=10)
        if result['success']:
            plan = result['data'].get('plan', 'unknown')
            print(f"{Colors.GREEN}✅ API bağlantısı başarılı - Plan: {plan}{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.RED}❌ API test başarısız: {result.get('error', 'Unknown error')}{Colors.ENDC}")
            return False
    
    def get_account_info(self):
        """Hesap bilgilerini al"""
        return api_request('/account/profile', self.api_key)
    
    def get_api_info(self):
        """API bilgilerini al"""
        return api_request('/api-info', self.api_key)
    
    def get_my_ip(self):
        """Kendi IP'ni al"""
        result = api_request('/tools/myip', self.api_key)
        if result['success']:
            return result['data'].get('ip')
        return None
    
    def get_http_headers(self):
        """HTTP headers al"""
        return api_request('/tools/httpheaders', self.api_key)
    
    def resolve_dns(self, hostnames):
        """DNS çözümlemesi"""
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        hostname_str = ','.join(hostnames[:10])  # Max 10 hostname
        return api_request(f'/dns/resolve?hostnames={hostname_str}', self.api_key)
    
    def reverse_dns(self, ips):
        """Reverse DNS"""
        if isinstance(ips, str):
            ips = [ips]
        ip_str = ','.join(ips[:10])  # Max 10 IP
        return api_request(f'/dns/reverse?ips={ip_str}', self.api_key)
    
    def get_host_info(self, ip):
        """Host bilgisi al"""
        return api_request(f'/shodan/host/{ip}', self.api_key)
    
    def get_host_count(self, query="*"):
        """Host sayısını al"""
        encoded_query = quote(query)
        return api_request(f'/shodan/host/count?query={encoded_query}', self.api_key)
    
    def get_search_facets(self):
        """Mevcut facet'leri al"""
        return api_request('/shodan/host/search/facets', self.api_key)
    
    def get_search_filters(self):
        """Mevcut filtreleri al"""
        return api_request('/shodan/host/search/filters', self.api_key)
    
    def get_search_tokens(self, query):
        """Query token'larını al"""
        encoded_query = quote(query)
        return api_request(f'/shodan/host/search/tokens?query={encoded_query}', self.api_key)
    
    def get_public_queries(self, page=1, sort="votes"):
        """Public query'leri al"""
        return api_request(f'/shodan/query?page={page}&sort={sort}', self.api_key)
    
    def get_ports(self):
        """Mevcut portları al"""
        return api_request('/shodan/ports', self.api_key)
    
    def get_protocols(self):
        """Mevcut protokolleri al"""
        return api_request('/shodan/protocols', self.api_key)
    
    def save_results(self, data, filename_prefix="shodan_result"):
        """Sonuçları kaydet"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.json"
        
        # outputs dizinini oluştur
        output_dir = Path("outputs")
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"{Colors.GREEN}💾 Sonuçlar kaydedildi: {filepath}{Colors.ENDC}")
            return str(filepath)
        except Exception as e:
            print(f"{Colors.RED}❌ Kaydetme hatası: {e}{Colors.ENDC}")
            return None

def display_banner():
    """Tool banner'ı göster"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                  🔍 Shodan OSS Tool v2.0                     ║
║              İstinye University - Penetration Testing        ║
║                     Furkan Dinçer - 2420191021              ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def display_account_info(data):
    """Hesap bilgilerini göster"""
    print(f"\n{Colors.HEADER}👤 HESAP BİLGİLERİ{Colors.ENDC}")
    print("="*60)
    
    info_items = [
        ("Plan", data.get('plan', 'Bilinmiyor')),
        ("Credits", data.get('credits', 'Bilinmiyor')),
        ("Display Name", data.get('display_name', 'N/A')),
        ("Member Since", data.get('created', 'N/A')),
    ]
    
    for label, value in info_items:
        print(f"{Colors.CYAN}{label:15}{Colors.ENDC}: {value}")

def display_api_info(data):
    """API bilgilerini göster"""
    print(f"\n{Colors.HEADER}🔧 API BİLGİLERİ{Colors.ENDC}")
    print("="*60)
    
    info_items = [
        ("Plan", data.get('plan', 'Bilinmiyor')),
        ("Query Credits", data.get('query_credits', 'Bilinmiyor')),
        ("Scan Credits", data.get('scan_credits', 'Bilinmiyor')),
        ("Monitored IPs", data.get('monitored_ips', 'Bilinmiyor')),
        ("Unlocked Left", data.get('unlocked_left', 'Bilinmiyor')),
        ("HTTPS", data.get('https', 'Bilinmiyor')),
        ("Telnet", data.get('telnet', 'Bilinmiyor')),
    ]
    
    for label, value in info_items:
        color = Colors.GREEN if value not in ['Bilinmiyor', 'N/A', 0] else Colors.YELLOW
        print(f"{Colors.CYAN}{label:15}{Colors.ENDC}: {color}{value}{Colors.ENDC}")

def display_host_info(data, ip):
    """Host bilgilerini göster"""
    print(f"\n{Colors.HEADER}🖥️  HOST BİLGİSİ: {ip}{Colors.ENDC}")
    print("="*70)
    
    # Temel bilgiler
    basic_info = [
        ("🏢 Organization", data.get('org', 'Bilinmiyor')),
        ("🌐 ISP", data.get('isp', 'Bilinmiyor')),
        ("🗺️  Country", data.get('country_name', 'N/A')),
        ("🏙️  City", data.get('city', 'N/A')),
        ("🔄 Last Update", data.get('last_update', 'N/A')),
        ("📡 OS", data.get('os', 'Bilinmiyor')),
    ]
    
    for label, value in basic_info:
        print(f"{label:20}: {value}")
    
    # Portlar
    ports = data.get('ports', [])
    if ports:
        print(f"\n{Colors.BLUE}📡 AÇIK PORTLAR ({len(ports)} adet):{Colors.ENDC}")
        # Portları gruplar halinde göster
        for i in range(0, len(ports), 15):
            port_group = ports[i:i+15]
            print(f"   {', '.join(map(str, port_group))}")
    
    # Güvenlik açıkları
    vulns = data.get('vulns', {})
    if vulns:
        print(f"\n{Colors.RED}⚠️  GÜVENLİK AÇIKLARI ({len(vulns)} adet):{Colors.ENDC}")
        for i, vuln in enumerate(list(vulns.keys())[:10], 1):
            cvss = vulns[vuln].get('cvss', 'N/A') if isinstance(vulns[vuln], dict) else 'N/A'
            print(f"   {i:2d}. {Colors.RED}{vuln}{Colors.ENDC} (CVSS: {cvss})")
        if len(vulns) > 10:
            print(f"   ... ve {len(vulns) - 10} adet daha")
    
    # Servisler (data array)
    services = data.get('data', [])
    if services:
        print(f"\n{Colors.GREEN}🔧 SERVİSLER ({len(services)} adet):{Colors.ENDC}")
        for i, service in enumerate(services[:5], 1):
            port = service.get('port', 'N/A')
            product = service.get('product', 'Bilinmiyor')
            version = service.get('version', '')
            transport = service.get('transport', 'tcp')
            
            print(f"   {i}. Port {port}/{transport}: {product} {version}")
            
            # Banner varsa ilk satırını göster
            banner = service.get('data', '')
            if banner:
                first_line = banner.split('\n')[0][:60]
                print(f"      └─ {Colors.YELLOW}{first_line}...{Colors.ENDC}")
        
        if len(services) > 5:
            print(f"   ... ve {len(services) - 5} servis daha")

def display_dns_results(data, query_type, query):
    """DNS sonuçlarını göster"""
    print(f"\n{Colors.HEADER}🌐 DNS {query_type.upper()}: {query}{Colors.ENDC}")
    print("="*60)
    
    if not data:
        print(f"{Colors.YELLOW}⚠️  Sonuç bulunamadı{Colors.ENDC}")
        return
    
    if query_type == "resolve":
        for hostname, ip_list in data.items():
            print(f"{Colors.CYAN}📍 {hostname}:{Colors.ENDC}")
            for ip in ip_list:
                print(f"   └─ {Colors.GREEN}{ip}{Colors.ENDC}")
    
    elif query_type == "reverse":
        for ip, hostname_list in data.items():
            print(f"{Colors.CYAN}🌐 {ip}:{Colors.ENDC}")
            for hostname in hostname_list:
                print(f"   └─ {Colors.GREEN}{hostname}{Colors.ENDC}")

def display_count_results(data, query):
    """Count sonuçlarını göster"""
    print(f"\n{Colors.HEADER}📊 HOST SAYISI: '{query}'{Colors.ENDC}")
    print("="*60)
    
    total = data.get('total', 0)
    print(f"{Colors.GREEN}Toplam Sonuç: {total:,}{Colors.ENDC}")
    
    # Facets varsa göster
    facets = data.get('facets', {})
    if facets:
        print(f"\n{Colors.BLUE}📈 İSTATİSTİKLER:{Colors.ENDC}")
        for facet_name, facet_data in facets.items():
            print(f"\n   {Colors.CYAN}{facet_name.upper()}:{Colors.ENDC}")
            for item in facet_data[:8]:
                count = item.get('count', 0)
                value = item.get('value', 'N/A')
                print(f"      {value}: {Colors.YELLOW}{count:,}{Colors.ENDC}")

def display_public_queries(data):
    """Public query'leri göster"""
    matches = data.get('matches', [])
    total = data.get('total', 0)
    
    print(f"\n{Colors.HEADER}📋 POPÜLER PUBLIC QUERY'LER{Colors.ENDC}")
    print("="*60)
    print(f"Toplam: {Colors.GREEN}{total:,}{Colors.ENDC} query, Gösterilen: {Colors.CYAN}{len(matches)}{Colors.ENDC}")
    
    for i, query in enumerate(matches[:10], 1):
        title = query.get('title', 'Başlıksız')
        description = query.get('description', 'Açıklama yok')
        votes = query.get('votes', 0)
        query_str = query.get('query', 'N/A')
        
        print(f"\n{Colors.BLUE}🔍 {i:2d}. {title}{Colors.ENDC}")
        print(f"    Query: {Colors.YELLOW}{query_str}{Colors.ENDC}")
        print(f"    Açıklama: {description[:80]}...")
        print(f"    👍 Votes: {Colors.GREEN}{votes}{Colors.ENDC}")

def display_ports_protocols(ports_data, protocols_data):
    """Port ve protokol bilgilerini güvenli şekilde göster"""
    print(f"\n{Colors.HEADER}📡 MEVCUT PORTLAR VE PROTOKOLLER{Colors.ENDC}")
    print("="*60)
    
    # Ports verisi - format kontrolü
    if ports_data:
        if isinstance(ports_data, list):
            # Direkt liste formatı
            ports = ports_data[:50]  # İlk 50 port
            print(f"{Colors.BLUE}📡 Popüler Portlar ({len(ports_data)} adet, ilk 50):{Colors.ENDC}")
        elif isinstance(ports_data, dict) and 'data' in ports_data:
            # Dict formatı
            ports = ports_data['data'][:50]
            print(f"{Colors.BLUE}📡 Popüler Portlar ({len(ports_data['data'])} adet, ilk 50):{Colors.ENDC}")
        else:
            ports = []
            print(f"{Colors.YELLOW}⚠️  Port verisi formatı tanınmıyor{Colors.ENDC}")
        
        if ports:
            # Portları 10'ar gruplar halinde göster
            for i in range(0, len(ports), 10):
                port_group = ports[i:i+10]
                port_str = ', '.join(map(str, port_group))
                print(f"   {Colors.GREEN}{port_str}{Colors.ENDC}")
    
    print()  # Boş satır
    
    # Protocols verisi - format kontrolü
    if protocols_data:
        if isinstance(protocols_data, list):
            # Direkt liste formatı
            protocols = protocols_data
            print(f"{Colors.BLUE}🔧 Desteklenen Protokoller ({len(protocols)} adet):{Colors.ENDC}")
        elif isinstance(protocols_data, dict) and 'data' in protocols_data:
            # Dict formatı
            protocols = protocols_data['data']
            print(f"{Colors.BLUE}🔧 Desteklenen Protokoller ({len(protocols)} adet):{Colors.ENDC}")
        else:
            protocols = []
            print(f"{Colors.YELLOW}⚠️  Protokol verisi formatı tanınmıyor{Colors.ENDC}")
        
        if protocols:
            # Protokolleri 8'er gruplar halinde göster
            for i in range(0, len(protocols), 8):
                protocol_group = protocols[i:i+8]
                protocol_str = ', '.join(protocol_group)
                print(f"   {Colors.GREEN}{protocol_str}{Colors.ENDC}")

def display_search_info(filters_data, facets_data):
    """Search bilgilerini göster"""
    print(f"\n{Colors.HEADER}🔍 SEARCH BİLGİLERİ{Colors.ENDC}")
    print("="*60)
    
    if filters_data:
        filters = filters_data if isinstance(filters_data, list) else filters_data.get('data', [])
        print(f"{Colors.BLUE}🎯 Mevcut Filtreler ({len(filters)} adet):{Colors.ENDC}")
        
        # Filtreleri kategoriler halinde göster
        for i in range(0, len(filters), 8):
            filter_group = filters[i:i+8]
            filter_str = ', '.join(filter_group)
            print(f"   {Colors.GREEN}{filter_str}{Colors.ENDC}")
    
    print()
    
    if facets_data:
        facets = facets_data if isinstance(facets_data, list) else facets_data.get('data', [])
        print(f"{Colors.BLUE}📊 Mevcut Facet'ler ({len(facets)} adet):{Colors.ENDC}")
        
        for i in range(0, len(facets), 8):
            facet_group = facets[i:i+8]
            facet_str = ', '.join(facet_group)
            print(f"   {Colors.CYAN}{facet_str}{Colors.ENDC}")

def validate_ip(ip):
    """IP geçerliliğini kontrol et"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_hostname(hostname):
    """Hostname geçerliliğini kontrol et"""
    if len(hostname) > 253:
        return False
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
    return re.match(pattern, hostname) is not None

def show_examples():
    """Kullanım örnekleri göster"""
    examples = f"""
{Colors.HEADER}📚 KULLANIM ÖRNEKLERİ{Colors.ENDC}
{'='*60}

{Colors.BLUE}📊 Temel Bilgiler:{Colors.ENDC}
  python improved_tool.py --account                    # Hesap bilgileri
  python improved_tool.py --api-info                   # API durumu
  python improved_tool.py --myip                       # Kendi IP'niz

{Colors.BLUE}🌐 DNS İşlemleri:{Colors.ENDC}
  python improved_tool.py --resolve google.com         # DNS çözümlemesi
  python improved_tool.py --reverse 8.8.8.8           # Reverse DNS
  python improved_tool.py --multi-domain google.com,github.com

{Colors.BLUE}🖥️  Host Analizi:{Colors.ENDC}
  python improved_tool.py --host 8.8.8.8              # Tek host
  python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1 # Çoklu host
  python improved_tool.py --host-detail 8.8.8.8       # Detaylı analiz

{Colors.BLUE}📊 İstatistikler:{Colors.ENDC}
  python improved_tool.py --count "port:80"            # HTTP sunucu sayısı
  python improved_tool.py --count "port:22"            # SSH sunucu sayısı
  python improved_tool.py --public-queries             # Popüler sorgular

{Colors.BLUE}🔧 Sistem Bilgileri:{Colors.ENDC}
  python improved_tool.py --ports-protocols            # Port/protokol listesi
  python improved_tool.py --search-info                # Search bilgileri
  python improved_tool.py --capabilities               # Mevcut yetenekler
"""
    print(examples)

def main():
    parser = argparse.ArgumentParser(
        description="Improved Shodan Tool v2.0 - OSS Plan Compatible",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Daha fazla örnek için: --examples parametresini kullanın"
    )
    
    # Temel işlemler
    parser.add_argument('--account', action='store_true', help='Hesap bilgilerini göster')
    parser.add_argument('--api-info', action='store_true', help='API bilgilerini göster')
    parser.add_argument('--myip', action='store_true', help='Kendi IP adresinizi görün')
    parser.add_argument('--capabilities', action='store_true', help='Mevcut yetenekleri test et')
    
    # DNS işlemleri
    parser.add_argument('--resolve', type=str, help='DNS çözümlemesi (hostname)')
    parser.add_argument('--reverse', type=str, help='Reverse DNS (IP adresi)')
    parser.add_argument('--multi-domain', type=str, help='Çoklu domain analizi (virgülle ayrılmış)')
    
    # Host analizi
    parser.add_argument('--host', type=str, help='Host bilgisi al (IP adresi)')
    parser.add_argument('--host-detail', type=str, help='Detaylı host analizi (IP adresi)')
    parser.add_argument('--multi-ip', type=str, help='Çoklu IP analizi (virgülle ayrılmış)')
    
    # İstatistikler
    parser.add_argument('--count', type=str, help='Host sayısı sorgusu (örn: "port:80")')
    parser.add_argument('--public-queries', action='store_true', help='Popüler public query\'leri göster')
    
    # Sistem bilgileri
    parser.add_argument('--ports-protocols', action='store_true', help='Mevcut port ve protokolleri listele')
    parser.add_argument('--search-info', action='store_true', help='Search filtre ve facet bilgileri')
    
    # Diğer
    parser.add_argument('--examples', action='store_true', help='Kullanım örnekleri göster')
    parser.add_argument('--save', action='store_true', help='Sonuçları dosyaya kaydet')
    parser.add_argument('--api-key', type=str, help='Shodan API anahtarı')
    
    args = parser.parse_args()
    
    # Banner göster
    display_banner()
    
    # Örnekler
    if args.examples:
        show_examples()
        return
    
    # Hiç argüman verilmemişse help göster
    if not any(vars(args).values()):
        parser.print_help()
        print(f"\n{Colors.CYAN}💡 Kullanım örnekleri için: --examples{Colors.ENDC}")
        return
    
    # API anahtarını al
    api_key = args.api_key or get_api_key()
    if not api_key:
        print(f"{Colors.RED}❌ API anahtarı bulunamadı!{Colors.ENDC}")
        return
    
    # Tool'u başlat
    try:
        tool = ShodanOSSTool(api_key)
    except Exception as e:
        print(f"{Colors.RED}❌ Tool başlatılamadı: {e}{Colors.ENDC}")
        return
    
    # Komutları işle
    try:
        saved_data = {}
        
        if args.capabilities:
            # Tüm yetenekleri test et
            print(f"\n{Colors.HEADER}🧪 YETENEK TESTİ{Colors.ENDC}")
            print("="*60)
            
            tests = [
                ("Account Info", lambda: tool.get_account_info()),
                ("API Info", lambda: tool.get_api_info()),
                ("My IP", lambda: tool.get_my_ip()),
                ("DNS Resolve", lambda: tool.resolve_dns("google.com")),
                ("Host Info", lambda: tool.get_host_info("8.8.8.8")),
                ("Ports", lambda: tool.get_ports()),
                ("Protocols", lambda: tool.get_protocols()),
            ]
            
            for test_name, test_func in tests:
                result = test_func()
                if (isinstance(result, dict) and result.get('success')) or result:
                    print(f"   {Colors.GREEN}✅ {test_name}{Colors.ENDC}")
                else:
                    print(f"   {Colors.RED}❌ {test_name}{Colors.ENDC}")
        
        elif args.account:
            result = tool.get_account_info()
            if result['success']:
                display_account_info(result['data'])
                if args.save:
                    saved_data['account_info'] = result['data']
            else:
                print(f"{Colors.RED}❌ Hesap bilgisi alınamadı: {result.get('error')}{Colors.ENDC}")
        
        elif args.api_info:
            result = tool.get_api_info()
            if result['success']:
                display_api_info(result['data'])
                if args.save:
                    saved_data['api_info'] = result['data']
            else:
                print(f"{Colors.RED}❌ API bilgisi alınamadı: {result.get('error')}{Colors.ENDC}")
        
        elif args.myip:
            my_ip = tool.get_my_ip()
            if my_ip:
                print(f"\n{Colors.GREEN}🌐 Sizin IP adresiniz: {my_ip}{Colors.ENDC}")
                
                # Bonus: Kendi IP'nizin detaylı bilgilerini de göster
                print(f"\n{Colors.CYAN}🔍 IP detaylarınızı alıyor...{Colors.ENDC}")
                host_result = tool.get_host_info(my_ip)
                if host_result['success']:
                    display_host_info(host_result['data'], my_ip)
                    if args.save:
                        saved_data['my_ip_info'] = {
                            'ip': my_ip,
                            'details': host_result['data']
                        }
                else:
                    print(f"{Colors.YELLOW}⚠️  IP detayları alınamadı: {host_result.get('error')}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}❌ IP adresi alınamadı{Colors.ENDC}")
        
        elif args.resolve:
            hostname = args.resolve
            if not validate_hostname(hostname):
                print(f"{Colors.RED}❌ Geçersiz hostname: {hostname}{Colors.ENDC}")
                return
            
            result = tool.resolve_dns(hostname)
            if result['success']:
                display_dns_results(result['data'], 'resolve', hostname)
                if args.save:
                    saved_data['dns_resolve'] = {
                        'hostname': hostname,
                        'results': result['data']
                    }
            else:
                print(f"{Colors.RED}❌ DNS çözümlemesi başarısız: {result.get('error')}{Colors.ENDC}")
        
        elif args.reverse:
            ip = args.reverse
            if not validate_ip(ip):
                print(f"{Colors.RED}❌ Geçersiz IP adresi: {ip}{Colors.ENDC}")
                return
            
            result = tool.reverse_dns(ip)
            if result['success']:
                display_dns_results(result['data'], 'reverse', ip)
                if args.save:
                    saved_data['reverse_dns'] = {
                        'ip': ip,
                        'results': result['data']
                    }
            else:
                print(f"{Colors.RED}❌ Reverse DNS başarısız: {result.get('error')}{Colors.ENDC}")
        
        elif args.multi_domain:
            domains = [domain.strip() for domain in args.multi_domain.split(',') if domain.strip()]
            invalid_domains = [d for d in domains if not validate_hostname(d)]
            
            if invalid_domains:
                print(f"{Colors.RED}❌ Geçersiz hostname'ler: {', '.join(invalid_domains)}{Colors.ENDC}")
                return
            
            if len(domains) > 10:
                print(f"{Colors.YELLOW}⚠️  Maksimum 10 domain desteklenir. İlk 10 tanesi işlenecek.{Colors.ENDC}")
                domains = domains[:10]
            
            print(f"{Colors.CYAN}🌐 Çoklu Domain Analizi ({len(domains)} domain){Colors.ENDC}")
            result = tool.resolve_dns(domains)
            if result['success']:
                display_dns_results(result['data'], 'resolve', ', '.join(domains))
                if args.save:
                    saved_data['multi_domain'] = {
                        'domains': domains,
                        'results': result['data']
                    }
            else:
                print(f"{Colors.RED}❌ DNS çözümlemesi başarısız: {result.get('error')}{Colors.ENDC}")
        
        elif args.host or args.host_detail:
            ip = args.host or args.host_detail
            if not validate_ip(ip):
                print(f"{Colors.RED}❌ Geçersiz IP adresi: {ip}{Colors.ENDC}")
                return
            
            result = tool.get_host_info(ip)
            if result['success']:
                display_host_info(result['data'], ip)
                
                # Detaylı analiz için ek bilgiler
                if args.host_detail:
                    print(f"\n{Colors.HEADER}🔍 DETAYLI ANALİZ{Colors.ENDC}")
                    print("="*60)
                    
                    # Reverse DNS de yap
                    reverse_result = tool.reverse_dns(ip)
                    if reverse_result['success'] and reverse_result['data'].get(ip):
                        hostnames = reverse_result['data'][ip]
                        print(f"{Colors.CYAN}🌐 Hostname'ler:{Colors.ENDC}")
                        for hostname in hostnames:
                            print(f"   └─ {hostname}")
                
                if args.save:
                    saved_data['host_info'] = {
                        'ip': ip,
                        'details': result['data']
                    }
            else:
                print(f"{Colors.RED}❌ Host bilgisi alınamadı: {result.get('error')}{Colors.ENDC}")
        
        elif args.multi_ip:
            ips = [ip.strip() for ip in args.multi_ip.split(',') if ip.strip()]
            invalid_ips = [ip for ip in ips if not validate_ip(ip)]
            
            if invalid_ips:
                print(f"{Colors.RED}❌ Geçersiz IP'ler: {', '.join(invalid_ips)}{Colors.ENDC}")
                return
            
            if len(ips) > 10:
                print(f"{Colors.YELLOW}⚠️  Maksimum 10 IP desteklenir. İlk 10 tanesi işlenecek.{Colors.ENDC}")
                ips = ips[:10]
            
            print(f"{Colors.HEADER}🔍 Çoklu IP Analizi ({len(ips)} IP){Colors.ENDC}")
            print("="*70)
            
            multi_results = {}
            for i, ip in enumerate(ips, 1):
                print(f"\n{Colors.BLUE}📍 {i}. IP: {ip}{Colors.ENDC}")
                result = tool.get_host_info(ip)
                if result['success']:
                    data = result['data']
                    info_items = [
                        ("🏢 Organization", data.get('org', 'N/A')),
                        ("🗺️  Location", f"{data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}"),
                        ("🌐 ISP", data.get('isp', 'N/A')),
                        ("📡 Open Ports", f"{len(data.get('ports', []))} adet"),
                        ("⚠️  Vulnerabilities", f"{len(data.get('vulns', {}))} adet"),
                    ]
                    
                    for label, value in info_items:
                        print(f"   {label}: {value}")
                    
                    multi_results[ip] = data
                else:
                    print(f"   {Colors.RED}❌ Bilgi alınamadı: {result.get('error')}{Colors.ENDC}")
                
                # Rate limiting için küçük bekleme
                if i < len(ips):
                    time.sleep(1)
            
            if args.save and multi_results:
                saved_data['multi_ip_analysis'] = multi_results
        
        elif args.count:
            query = args.count
            result = tool.get_host_count(query)
            if result['success']:
                display_count_results(result['data'], query)
                if args.save:
                    saved_data['count_query'] = {
                        'query': query,
                        'results': result['data']
                    }
            else:
                print(f"{Colors.RED}❌ Count sorgusu başarısız: {result.get('error')}{Colors.ENDC}")
        
        elif args.public_queries:
            result = tool.get_public_queries()
            if result['success']:
                display_public_queries(result['data'])
                if args.save:
                    saved_data['public_queries'] = result['data']
            else:
                print(f"{Colors.RED}❌ Public query'ler alınamadı: {result.get('error')}{Colors.ENDC}")
        
        elif args.ports_protocols:
            print(f"{Colors.CYAN}🔄 Port ve protokol bilgileri alınıyor...{Colors.ENDC}")
            
            ports_result = tool.get_ports()
            protocols_result = tool.get_protocols()
            
            ports_data = None
            protocols_data = None
            
            if ports_result['success']:
                ports_data = ports_result['data']
                print(f"{Colors.GREEN}✅ Port bilgileri alındı{Colors.ENDC}")
            else:
                print(f"{Colors.RED}❌ Port bilgileri alınamadı: {ports_result.get('error')}{Colors.ENDC}")
            
            if protocols_result['success']:
                protocols_data = protocols_result['data']
                print(f"{Colors.GREEN}✅ Protokol bilgileri alındı{Colors.ENDC}")
            else:
                print(f"{Colors.RED}❌ Protokol bilgileri alınamadı: {protocols_result.get('error')}{Colors.ENDC}")
            
            if ports_data or protocols_data:
                display_ports_protocols(ports_data, protocols_data)
                if args.save:
                    saved_data['ports_protocols'] = {
                        'ports': ports_data,
                        'protocols': protocols_data
                    }
            else:
                print(f"{Colors.RED}❌ Hiçbir bilgi alınamadı{Colors.ENDC}")
        
        elif args.search_info:
            print(f"{Colors.CYAN}🔄 Search bilgileri alınıyor...{Colors.ENDC}")
            
            filters_result = tool.get_search_filters()
            facets_result = tool.get_search_facets()
            
            filters_data = None
            facets_data = None
            
            if filters_result['success']:
                filters_data = filters_result['data']
                print(f"{Colors.GREEN}✅ Filter bilgileri alındı{Colors.ENDC}")
            else:
                print(f"{Colors.RED}❌ Filter bilgileri alınamadı: {filters_result.get('error')}{Colors.ENDC}")
            
            if facets_result['success']:
                facets_data = facets_result['data']
                print(f"{Colors.GREEN}✅ Facet bilgileri alındı{Colors.ENDC}")
            else:
                print(f"{Colors.RED}❌ Facet bilgileri alınamadı: {facets_result.get('error')}{Colors.ENDC}")
            
            if filters_data or facets_data:
                display_search_info(filters_data, facets_data)
                if args.save:
                    saved_data['search_info'] = {
                        'filters': filters_data,
                        'facets': facets_data
                    }
            else:
                print(f"{Colors.RED}❌ Hiçbir search bilgisi alınamadı{Colors.ENDC}")
        
        # Sonuçları kaydet
        if args.save and saved_data:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            saved_data['scan_info'] = {
                'timestamp': timestamp,
                'tool_version': '2.0',
                'command_used': ' '.join(sys.argv)
            }
            
            filename = tool.save_results(saved_data, "shodan_analysis")
            if filename:
                print(f"\n{Colors.GREEN}💾 Tüm sonuçlar kaydedildi: {filename}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}🛑 İşlem kullanıcı tarafından durduruldu{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Beklenmeyen hata: {e}{Colors.ENDC}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
