# Shodan Device Scanner - Usage Examples v2.0

## 📚 Gelişmiş Kullanım Örnekleri / Advanced Usage Examples

Bu dokümant, Shodan Device Scanner v2.0'ın tüm özelliklerini ve OSS planında çalışan gelişmiş komutları içerir.

### 🚀 Hızlı Başlangıç / Quick Start

```bash
# Tool'u tanımak için örnekleri görüntüle
python improved_tool.py --examples

# Mevcut yetenekleri test et
python improved_tool.py --capabilities

# Kendi IP'nizi öğrenin + otomatik detaylı analiz
python improved_tool.py --myip

# Yardım menüsü
python improved_tool.py --help
```

## 🔧 Temel Sistem Bilgileri / Basic System Information

### 📊 Hesap ve API Durumu
```bash
# Hesap bilgilerinizi görüntüleyin
python improved_tool.py --account

# API durumu ve plan bilgileri
python improved_tool.py --api-info

# Kendi IP adresiniz + ISP bilgileri + host detayları
python improved_tool.py --myip
```

**Örnek Çıktı:**
```
👤 HESAP BİLGİLERİ
==================================================
Plan           : oss
Credits        : Bilinmiyor
Display Name   : your_username
Member Since   : 2024-11-20T10:30:00.000000
```

### 🧪 Yetenek Testi
```bash
# Tüm özelliklerin çalışıp çalışmadığını test et
python improved_tool.py --capabilities
```

## 🌐 DNS İşlemleri / DNS Operations

### Tek Domain Analizi
```bash
# Basit DNS çözümlemesi
python improved_tool.py --resolve google.com
python improved_tool.py --resolve github.com
python improved_tool.py --resolve stackoverflow.com

# Türk siteleri
python improved_tool.py --resolve sabah.com.tr
python improved_tool.py --resolve hürriyet.com.tr
python improved_tool.py --resolve trt.net.tr
```

### Reverse DNS
```bash
# Popüler DNS sunucuları
python improved_tool.py --reverse 8.8.8.8          # Google DNS
python improved_tool.py --reverse 1.1.1.1          # Cloudflare DNS
python improved_tool.py --reverse 208.67.222.222   # OpenDNS

# Türk ISP'leri
python improved_tool.py --reverse 195.175.39.39    # Turkcell
python improved_tool.py --reverse 212.156.70.7     # Vodafone TR
```

### Çoklu Domain Analizi
```bash
# Popüler siteler
python improved_tool.py --multi-domain google.com,youtube.com,facebook.com

# Teknoloji siteleri
python improved_tool.py --multi-domain github.com,stackoverflow.com,reddit.com

# Türk siteleri
python improved_tool.py --multi-domain sabah.com.tr,hürriyet.com.tr,ntv.com.tr

# Üniversiteler
python improved_tool.py --multi-domain istinye.edu.tr,itu.edu.tr,boun.edu.tr

# Maksimum 10 domain desteklenir
python improved_tool.py --multi-domain site1.com,site2.com,site3.com,site4.com,site5.com,site6.com,site7.com,site8.com,site9.com,site10.com
```

## 🖥️ Host Analizi / Host Analysis

### Tek Host Detaylı Analizi
```bash
# Basit host bilgisi
python improved_tool.py --host 8.8.8.8

# Detaylı host analizi (reverse DNS dahil)
python improved_tool.py --host-detail 8.8.8.8
python improved_tool.py --host-detail 1.1.1.1

# Üniversite sunucuları
python improved_tool.py --host-detail 193.140.100.100  # İTÜ örnek IP
```

**Detaylı Analiz Örnek Çıktı:**
```
🖥️  HOST BİLGİSİ: 8.8.8.8
======================================================================
🏢 Organization    : Google LLC
🌐 ISP            : Google LLC
🗺️  Country        : United States
🏙️  City           : Mountain View
🔄 Last Update    : 2024-11-20T12:00:00.000000
📡 OS             : Bilinmiyor

📡 AÇIK PORTLAR (2 adet):
   53, 443

🔧 SERVİSLER (2 adet):
   1. Port 53/udp: Bilinmiyor 
      └─ DNS response...
   2. Port 443/tcp: Bilinmiyor 
      └─ HTTP/1.1 404 Not Found...

🔍 DETAYLI ANALİZ
======================================================================
🌐 Hostname'ler:
   └─ dns.google
```

### Çoklu Host Analizi
```bash
# DNS sunucuları karşılaştırması
python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1,208.67.222.222

# CDN sunucuları
python improved_tool.py --multi-ip 151.101.1.140,151.101.65.140,151.101.129.140

# Türk ISP DNS'leri
python improved_tool.py --multi-ip 195.175.39.39,212.156.70.7,212.252.169.150

# Maksimum 10 IP desteklenir
python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1,4.4.4.4,208.67.222.222,9.9.9.9
```

**Çoklu Analiz Örnek Çıktı:**
```
🔍 Çoklu IP Analizi (3 IP)
======================================================================

📍 1. IP: 8.8.8.8
   🏢 Organization: Google LLC
   🗺️  Location: Mountain View, United States
   🌐 ISP: Google LLC
   📡 Open Ports: 2 adet
   ⚠️  Vulnerabilities: 0 adet

📍 2. IP: 1.1.1.1
   🏢 Organization: Cloudflare, Inc.
   🗺️  Location: San Francisco, United States
   🌐 ISP: Cloudflare, Inc.
   📡 Open Ports: 3 adet
   ⚠️  Vulnerabilities: 0 adet
```

## 📊 İstatistikler ve Veritabanı Bilgileri / Statistics and Database Info

### Host Sayısı Sorguları
```bash
# Genel portlar
python improved_tool.py --count "port:80"           # HTTP sunucuları
python improved_tool.py --count "port:443"          # HTTPS sunucuları
python improved_tool.py --count "port:22"           # SSH servisleri
python improved_tool.py --count "port:21"           # FTP servisleri
python improved_tool.py --count "port:25"           # SMTP servisleri

# Veritabanları
python improved_tool.py --count "port:3306"         # MySQL
python improved_tool.py --count "port:5432"         # PostgreSQL
python improved_tool.py --count "port:27017"        # MongoDB
python improved_tool.py --count "port:6379"         # Redis

# Özel serviser
python improved_tool.py --count "port:3389"         # RDP
python improved_tool.py --count "port:5900"         # VNC
python improved_tool.py --count "port:1433"         # MSSQL
python improved_tool.py --count "port:5984"         # CouchDB

# Ürün bazlı sorgular (OSS planında çalışabilir)
python improved_tool.py --count "apache"
python improved_tool.py --count "nginx"
python improved_tool.py --count "microsoft"
```

**Count Sorgusu Örnek Çıktı:**
```
📊 HOST SAYISI: 'port:80'
======================================================================
Toplam Sonuç: 122,055,336

📈 İSTATİSTİKLER:

   COUNTRY:
      United States: 45,123,456
      China: 12,345,678
      Germany: 8,765,432
      Russia: 6,543,210
      United Kingdom: 4,321,098

   ORG:
      Amazon.com: 2,345,678
      Google: 1,234,567
      Microsoft Corporation: 987,654
      Cloudflare: 765,432
      OVH SAS: 543,210
```

### Popüler Query'ler
```bash
# Shodan topluluğunun en popüler sorguları
python improved_tool.py --public-queries
```

## 🔧 Sistem ve Protokol Bilgileri / System and Protocol Information

### Port ve Protokol Listesi
```bash
# Shodan'ın taradığı tüm portlar ve protokoller
python improved_tool.py --ports-protocols
```

**Örnek Çıktı:**
```
📡 MEVCUT PORTLAR VE PROTOKOLLER
======================================================================
📡 Popüler Portlar (100 adet, ilk 50):
   21, 22, 23, 25, 53, 80, 110, 143, 443, 993
   995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
   ...

🔧 Desteklenen Protokoller (15 adet):
   http, https, ssh, ftp, telnet, smtp, dns, mysql
   postgresql, mongodb, redis, vnc, rdp, smb, snmp
```

### Search Bilgileri
```bash
# Mevcut filtreler ve facet'ler
python improved_tool.py --search-info
```

## 💾 Sonuç Kaydetme / Result Saving

### Otomatik Kaydetme
```bash
# Herhangi bir komutla --save ekleyerek sonuçları JSON formatında kaydet

# Hesap bilgilerini kaydet
python improved_tool.py --account --save

# Host analizini kaydet
python improved_tool.py --host-detail 8.8.8.8 --save

# Çoklu IP analizini kaydet
python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1,4.4.4.4 --save

# DNS analizini kaydet
python improved_tool.py --multi-domain google.com,github.com,youtube.com --save

# Count sorgusunu kaydet
python improved_tool.py --count "port:80" --save

# Public query'leri kaydet
python improved_tool.py --public-queries --save
```

**Kayıt Formatı:**
```json
{
  "scan_info": {
    "timestamp": "20241120_143022",
    "tool_version": "2.0",
    "command_used": "python improved_tool.py --host-detail 8.8.8.8 --save"
  },
  "host_info": {
    "ip": "8.8.8.8",
    "details": {
      "org": "Google LLC",
      "country_name": "United States",
      "ports": [53, 443],
      "vulns": {}
    }
  }
}
```

## 🔍 Gelişmiş Kullanım Senaryoları / Advanced Usage Scenarios

### Penetration Testing Reconnaissance
```bash
# 1. Kendi ağınızı analiz edin
python improved_tool.py --myip --save

# 2. Hedef organizasyonun DNS sunucularını tespit edin
python improved_tool.py --multi-domain target.com,mail.target.com,www.target.com --save

# 3. Bulduğunuz IP'leri detaylı analiz edin
python improved_tool.py --multi-ip 1.2.3.4,1.2.3.5,1.2.3.6 --save

# 4. Servislerin yaygınlığını kontrol edin
python improved_tool.py --count "port:22" --save
python improved_tool.py --count "port:80" --save
```

### Threat Intelligence Gathering
```bash
# 1. Popüler saldırı vektörlerini araştırın
python improved_tool.py --public-queries --save

# 2. Yaygın servislerin istatistiklerini toplayın
python improved_tool.py --count "port:3389"  # RDP attacks
python improved_tool.py --count "port:22"    # SSH brute force
python improved_tool.py --count "port:1433"  # SQL Server

# 3. DNS infrastructure mapping
python improved_tool.py --multi-domain dns1.target.com,dns2.target.com --save
```

### Academic Research
```bash
# 1. Internet altyapısı araştırması
python improved_tool.py --ports-protocols --save

# 2. DNS ecosystem analizi
python improved_tool.py --multi-domain edu.tr,gov.tr,com.tr --save

# 3. Global servis dağılımı
python improved_tool.py --count "port:80" --save
python improved_tool.py --count "port:443" --save
```

## 🔒 Güvenlik ve Etik / Security and Ethics

### ✅ İzin Verilen Kullanımlar / Authorized Use
- **Kendi sistemlerinizi test etmek**
- **İzin alınmış penetration testing**
- **Akademik araştırma** (etik sınırlar içinde)
- **Threat intelligence** toplama
- **DNS infrastructure** araştırması
- **Public bilgi** toplama

### ❌ İzin Verilmeyen Kullanımlar / Unauthorized Use
- **İzinsiz sistem tarama**
- **Kötü amaçlı saldırılar**
- **Gizlilik ihlalleri**
- **Sistem sabotajı**
- **Yasadışı faaliyetler**

### 📋 En İyi Uygulamalar / Best Practices

```bash
# Rate limiting'e uyun - çok fazla sorgu yapmayın
python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1  # ✅ Az sayıda IP

# Sonuçları güvenli şekilde saklayın
python improved_tool.py --host 8.8.8.8 --save  # ✅ Otomatik kaydetme

# Sadece gerekli verileri toplayın
python improved_tool.py --count "port:22" # ✅ Spesifik sorgular

# OSS plan sınırlarına uyun
python improved_tool.py --capabilities  # ✅ Önce yetenekleri test edin
```

## 🐛 Sorun Giderme / Troubleshooting

### API Key Hataları
```bash
# API key'i test et
python improved_tool.py --api-info

# Farklı key ile test
python improved_tool.py --api-key "NEW_KEY" --account

# Çevre değişkenini ayarla
export SHODAN_API_KEY="your_key_here"
python improved_tool.py --account
```

### Rate Limiting
```bash
# Daha az sonuç al
python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1  # 2 IP instead of 10

# Tek seferde test et
python improved_tool.py --host 8.8.8.8
```

### OSS Plan Sınırları
```bash
# Çalışan özellikleri test et
python improved_tool.py --capabilities

# Basit komutlarla başla
python improved_tool.py --myip
python improved_tool.py --account
```

### Hata Mesajları
```bash
# Hata detayları için debug mode
python improved_tool.py --host 8.8.8.8 --debug
```

## 📊 Çıktı Formatları / Output Formats

### Terminal Çıktısı
- 🌈 **Renkli metin** - Kolay okuma
- 📊 **Düzenli tablolar** - Structured data
- 🎯 **Kategorize bilgiler** - Mantıklı gruplama
- ✅ **Status göstergeleri** - Başarı/hata

### JSON Kayıtları
```bash
# Kayıtlar outputs/ klasöründe saklanır
ls outputs/
shodan_analysis_20241120_143022.json
shodan_analysis_20241120_144530.json
```

## 🔗 Yararlı Linkler / Useful Links

- **Shodan Account**: https://account.shodan.io/
- **Shodan Help**: https://help.shodan.io/
- **Academic Access**: https://help.shodan.io/the-basics/academic-access
- **API Documentation**: https://developer.shodan.io/
- **Search Filters**: https://beta.shodan.io/search/filters
- **İstinye University**: https://www.istinye.edu.tr/

## 💡 Pro İpuçları / Pro Tips

```bash
# 1. Sonuçları kaydetmeyi unutmayın
python improved_tool.py --myip --save

# 2. Çoklu analiz kullanın - daha verimli
python improved_tool.py --multi-ip 8.8.8.8,1.1.1.1,4.4.4.4

# 3. Önce yetenekleri test edin
python improved_tool.py --capabilities

# 4. Rate limiting'e dikkat edin
# Çok fazla IP/domain aynı anda sorgulamayın

# 5. DNS analizi ile başlayın - güvenli
python improved_tool.py --resolve google.com

# 6. Count sorguları ile trend analizi yapın
python improved_tool.py --count "port:22"
```

## ⚖️ Yasal Uyarı / Legal Disclaimer

Bu araç yalnızca **eğitim ve yetkili güvenlik testleri** için tasarlanmıştır. Kullanıcılar:

- ✅ **Yerel yasalara uymalıdır**
- ✅ **Hedef sistemler için izin almalıdır**
- ✅ **Etik hacking prensiplerini takip etmelidir**
- ✅ **Sorumlu açıklama ilkelerini uygulamalıdır**

**This tool is designed for education and authorized security testing only. Users must:**
- ✅ **Comply with local laws**
- ✅ **Obtain permission for target systems**
- ✅ **Follow ethical hacking principles**
- ✅ **Apply responsible disclosure practices**

---

**Proje Bilgileri:**
- **Üniversite**: İstinye University
- **Ders**: Penetration Testing
- **Öğrenci**: Furkan Dinçer (2420191021)
- **Tool Version**: 2.0
- **Son Güncelleme**: Kasım 2024

**İletişim:**
- **Email**: hi@furkandincer.com
- **GitHub**: https://github.com/frkndncr/shodan-device-scanner
- **Issues**: https://github.com/frkndncr/shodan-device-scanner/issues