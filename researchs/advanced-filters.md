# Advanced Shodan Filters

## Overview / Genel Bakış
Advanced Shodan filters (e.g., `vuln`, `ssl.ja3s`) enable precise targeting of devices for security analysis. This research explores their use in penetration testing.  
Gelişmiş Shodan filtreleri (örneğin, `vuln`, `ssl.ja3s`), güvenlik analizi için cihazları hassas bir şekilde hedeflemeyi sağlar. Bu araştırma, sızma testinde kullanımlarını inceler.

## Key Findings / Temel Bulgular
- **Vulnerability Filters**: The `vuln` filter identifies devices with known CVEs (e.g., `vuln:CVE-2014-0160` for Heartbleed).  
  **Güvenlik Açığı Filtreleri**: `vuln` filtresi, bilinen CVE'lere sahip cihazları tespit eder (örneğin, Heartbleed için `vuln:CVE-2014-0160`).  
- **SSL/TLS Fingerprinting**: Filters like `ssl.ja3s` and `ssl.jarm` help identify specific server configurations.  
  **SSL/TLS Parmak İzi**: `ssl.ja3s` ve `ssl.jarm` gibi filtreler, belirli sunucu yapılandırmalarını tanımlamaya yardımcı olur.  
- **Access Requirements**: Advanced filters require paid Shodan plans.  
  **Erişim Gereksinimleri**: Gelişmiş filtreler, ücretli Shodan planları gerektirir.

## Source / Kaynak
- [Shodan Filter Reference](https://beta.shodan.io/search/filters)  
- Commit Date: May 29, 2025
