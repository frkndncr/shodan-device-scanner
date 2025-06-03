# Shodan Device Scanner - Usage Examples

## 📚 Kullanım Örnekleri / Usage Examples

### 🚀 Hızlı Başlangıç / Quick Start

```bash
# İnteraktif mod - tavsiye edilen
python src/main.py --interactive

# Yardım menüsü
python src/main.py --help

# Mevcut şablonları göster
python src/main.py --list-templates
```

### 🎯 Şablon Tabanlı Taramalar / Template-Based Scans

```bash
# Türkiye'deki web sunucuları
python src/main.py --template web_servers_tr --max-results 100

# Kritik güvenlik açıkları
python src/main.py --template vulnerable_systems --format html

# Açık veritabanları
python src/main.py --template exposed_databases --output "db_scan_results"

# IoT cihazları
python src/main.py --template iot_devices --max-results 50

# Endüstriyel kontrol sistemleri (dikkatli kullanın!)
python src/main.py --template industrial_systems --max-results 25
```

### 🔧 Özel Sorgular / Custom Queries

```bash
# Apache sunucuları Türkiye'de
python src/main.py --query "product:Apache country:TR" --max-results 200

# SSH servisleri
python src/main.py --query "port:22 country:TR" --format csv

# Zayıf SSL sertifikaları
python src/main.py --query "port:443 ssl.version:tlsv1 country:TR"

# MongoDB örnekleri
python src/main.py --query "product:MongoDB port:27017 country:TR"

# Belirli bir organizasyon
python src/main.py --query 'org:"İstinye University"' --max-results 50
```

### 📊 Gelişmiş Örnekler / Advanced Examples

```bash
# Çoklu CVE taraması
python src/main.py --query "vuln:CVE-2024-3400 OR vuln:CVE-2024-21887" --format json

# Belirli şehirler
python src/main.py --query "city:Istanbul OR city:Ankara port:80,443" --max-results 500

# Kamera sistemleri
python src/main.py --query "device:webcam country:TR" --output "camera_scan"

# VPN sunucuları
python src/main.py --query "port:1723,1194,4500 country:TR" --format html
```

### 🔍 Araştırma ve İstihbarat / Research and Intelligence

```bash
# Botnet C&C sunucuları (dikkat: sadece araştırma amaçlı)
python src/main.py --query "product:Cobalt Strike"

# Tor exit node'ları
python src/main.py --query "product:Tor"

# Kripto para madenciliği
python src/main.py --query "product:xmrig OR product:mining"

# Honeypot tespiti
python src/main.py --query "product:Kippo OR product:Cowrie"
```

### 🏢 Kurumsal Güvenlik Taramaları / Enterprise Security Scans

```bash
# Finansal kuruluşlar
python src/main.py --query 'org:"bank" OR org:"banka" country:TR' --max-results 100

# Üniversiteler
python src/main.py --query 'org:"university" OR org:"üniversitesi" country:TR'

# Devlet kurumları (dikkatli kullanın!)
python src/main.py --query 'org:"gov.tr" OR hostname:"*.gov.tr"' --max-results 50

# Hastaneler
python src/main.py --query 'org:"hospital" OR org:"hastane" country:TR'
```

### ⚙️ Yapılandırma Örnekleri / Configuration Examples

```bash
# Yapılandırma sihirbazı
python src/main.py --config

# API anahtarını komut satırından ver
python src/main.py --api-key "YOUR_API_KEY" --template web_servers_tr

# Verbose logging ile
python src/main.py --verbose --template vulnerable_systems
```

## 🛡️ Güvenlik ve Etik / Security and Ethics

### ✅ İzin Verilen Kullanımlar / Authorized Use
- Kendi sistemlerinizi test etmek
- İzin alınmış penetration testing
- Akademik araştırma (etik sınırlar içinde)
- Güvenlik farkındalığı eğitimleri
- Threat intelligence toplama

### ❌ İzin Verilmeyen Kullanımlar / Unauthorized Use
- İzinsiz sistem tarama
- Kötü amaçlı saldırılar
- Gizlilik ihlalleri
- Sistem sabotajı
- Yasadışı faaliyetler

### 📋 En İyi Uygulamalar / Best Practices

```bash
# Rate limiting'e uyun
python src/main.py --template web_servers_tr --max-results 50

# Sonuçları güvenli şekilde saklayın
python src/main.py --query "port:22 country:TR" --output "secure_scan" --format json

# Sadece gerekli verileri toplayın
python src/main.py --template exposed_databases --max-results 25
```

## 📈 Sonuç Analizi / Result Analysis

### JSON Çıktısı Analizi
```python
import json

# Sonuçları yükle
with open('outputs/shodan_scan_20250529_143022.json', 'r') as f:
    data = json.load(f)

# Toplam host sayısı
print(f"Total hosts: {data['scan_info']['total_hosts']}")

# Risk dağılımı
stats = data['scan_info']['statistics']
print(f"High risk hosts: {stats['risk_distribution']['high']}")

# En çok bulunan portlar
for port, count in stats['top_ports'].items():
    print(f"Port {port}: {count} hosts")
```

### CSV Analizi (Excel'de)
1. CSV dosyasını Excel'de açın
2. Risk Score kolununa göre sıralayın
3. Pivot table oluşturun:
   - Rows: Country
   - Values: Count of IP
4. Grafik oluşturun

### HTML Raporu
- Tarayıcıda açın
- Risk seviyelerine göre renk kodlaması
- Interaktif tablo
- Yazdırma dostu format

## 🔧 Sorun Giderme / Troubleshooting

### API Key Hataları
```bash
# API key'i kontrol et
python src/main.py --config

# Yeni key ile test
python src/main.py --api-key "NEW_KEY" --list-templates
```

### Rate Limiting
```bash
# Daha yavaş tarama
python src/main.py --template web_servers_tr --max-results 10

# Gecikme ekle (config'de ayarlanabilir)
# delay_between_queries = 5
```

### Bellek Sorunları
```bash
# Daha az sonuç al
python src/main.py --template vulnerable_systems --max-results 100

# CSV formatı kullan (daha az bellek)
python src/main.py --query "port:80 country:TR" --format csv --max-results 50
```

## 📞 Destek / Support

- **GitHub Issues**: [Repository Issues](https://github.com/frkndncr/shodan-device-scanner/issues)
- **Documentation**: README.md
- **Email**: hi@furkandincer.com
- **University**: İstinye University - Cybersecurity Course

## ⚖️ Yasal Uyarı / Legal Disclaimer

Bu araç yalnızca eğitim ve yetkili güvenlik testleri için tasarlanmıştır. Kullanıcılar:
- Yerel yasalara uymalıdır
- Hedef sistemler için izin almalıdır  
- Etik hacking prensiplerini takip etmelidir
- Sorumlu açıklama ilkelerini uygulamalıdır

This tool is designed for education and authorized security testing only. Users must:
- Comply with local laws
- Obtain permission for target systems
- Follow ethical hacking principles
- Apply responsible disclosure practices