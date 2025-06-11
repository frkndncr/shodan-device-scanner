# Shodan Device Scanner

**Language Count**: 1 (Python)  
**Top Language**: Python  
**Last Commit**: May 29, 2025  
**License**: MIT License  
**Status**: In Development  
**Contributions**: Furkan Dinçer | 2420191021 İÖ

## Proje Adı
Shodan Device Scanner

## A brief, engaging description of your project / Projenizin kısa ve ilgi çekici bir açıklaması
Developed for the Penetration Testing course at İstinye University, this project harnesses the Shodan API to scan and analyze internet-connected devices, such as servers and IoT devices, using tailored filters like country, port, or vulnerabilities. It delivers structured JSON outputs for security researchers, adhering to ethical and legal standards for responsible use in penetration testing.  
İstinye Üniversitesi Sızma Testi dersi için geliştirilen bu proje, Shodan API'sini kullanarak sunucular ve IoT cihazları gibi internete bağlı cihazları ülke, port veya güvenlik açıkları gibi özelleştirilmiş filtrelerle tarar ve analiz eder. Güvenlik araştırmacıları için yapılandırılmış JSON çıktıları sunar ve sızma testinde etik ve yasal standartlara uygun şekilde kullanılır.

## Features / Özellikler
- **Feature 1: Flexible Device Scanning**  
  Scan devices with customizable Shodan filters (e.g., `server:nginx country:TR` for nginx servers in Turkey).  
  **Özellik 1: Esnek Cihaz Taraması**  
  Özelleştirilebilir Shodan filtreleriyle cihaz tarama (örneğin, Türkiye'deki nginx sunucuları için `server:nginx country:TR`).  
- **Feature 2: Structured JSON Output**  
  Save detailed scan results (IP, port, OS, organization) in JSON format for easy analysis and reporting.  
  **Özellik 2: Yapılandırılmış JSON Çıktısı**  
  IP, port, işletim sistemi ve organizasyon gibi detaylı tarama sonuçlarını analiz ve raporlama için JSON formatında kaydetme.  
- **Feature 3: Ethical Penetration Testing**  
  Built for ethical security research, ensuring compliance with Shodan's policies and legal boundaries.  
  **Özellik 3: Etik Sızma Testi**  
  Shodan'ın politikalarına ve yasal sınırlara uygun, etik güvenlik araştırmaları için tasarlandı.  
- **Feature 4: Future-Ready Framework**  
  Extensible for adding a web interface or data visualizations (e.g., charts) to enhance usability.  
  **Özellik 4: Geleceğe Hazır Çerçeve**  
  Kullanılabilirliği artırmak için web arayüzü veya veri görselleştirmeleri (örneğin, grafikler) eklemek için genişletilebilir.  

## Team / Ekip
- **2420191021 - Furkan Dinçer**: Project Lead, responsible for design, development, API integration, and documentation.  
  **Furkan Dinçer**: Proje Lideri, tasarım, geliştirme, API entegrasyonu ve dokümantasyon sorumlusu.  

## Roadmap / Yol Haritası
See our detailed plans in [ROADMAP.md](ROADMAP.md), outlining future enhancements like a web interface and data visualization.  
Ayrıntılı planlar için [ROADMAP.md](ROADMAP.md) dosyasına bakın.

## Researchs / Araştırmalar
| Topic / Başlık | Link | Description / Açıklama |
|----------------|---------------|-----------------------|
| Shodan API for Penetration Testing | [researchs/shodan-api.md](researchs/shodan-api.md) | In-depth analysis of Shodan API's capabilities for identifying vulnerable devices in penetration testing. / Sızma testinde savunmasız cihazları tespit etmek için Shodan API'nin kabiliyetlerinin derinlemesine incelenmesi. |
| IoT Security Trends 2025 | [researchs/iot-security.md](researchs/iot-security.md) | Exploration of 2025 IoT security challenges and Shodan's role in detecting exposed devices. / 2025 IoT güvenlik zorluklarının ve Shodan'ın açıkta kalan cihazları tespit etmedeki rolünün incelenmesi. |
| Advanced Shodan Filters | [researchs/advanced-filters.md](researchs/advanced-filters.md) | Overview of advanced Shodan filters (e.g., `vuln`, `ssl.ja3s`) for precise device targeting. / Hassas cihaz hedefleme için gelişmiş Shodan filtrelerinin (örneğin, `vuln`, `ssl.ja3s`) genel bakışı. |

## Installation / Kurulum
**Clone the project / Depoyu klonlayın**:
```bash
git clone https://github.com/frkndncr/shodan-device-scanner.git
cd shodan-device-scanner
```

**Set up virtual environment / Sanal ortam oluşturun** (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**Install dependencies / Bağımlılıkları yükleyin**:
```bash
pip install -r requirements.txt
```

**Get a Shodan API key / Shodan API anahtarı alın**:
- Sign up at [shodan.io](https://www.shodan.io) to obtain a free or paid API key.  
  [shodan.io](https://www.shodan.io/) adresinden ücretsiz veya ücretli bir API anahtarı alın.  
- Replace `YOUR_API_KEY` in `src/main.py` with your API key.  
  `src/main.py` dosyasındaki `YOUR_API_KEY` kısmını kendi anahtarınızla değiştirin.  

## Usage / Kullanım
**Run the project / Projeyi çalıştırın**:
```bash
python src/main.py
```

**Steps / Adımlar**:
- **Prepare input data**:  
  Edit the `query` variable in `src/main.py` with a Shodan search query (e.g., `server:nginx country:TR` for nginx servers in Turkey).  
  **Giriş verilerini hazırlayın**: `src/main.py` dosyasındaki `query` değişkenini bir Shodan sorgusuyla güncelleyin.  
- **Run the script**: Execute `src/main.py` to scan devices and retrieve results.  
  **Betiği çalıştırın**: Cihazları taramak ve sonuçları elde etmek için çalıştırın.  
- **Check output**:  
  Results are saved as JSON files (e.g., `results_YYYYMMDD_HHMMSS.json`) in the `outputs/` folder.  
  **Sonuçları kontrol edin**: JSON dosyaları olarak `outputs/` klasöründe kaydedilir.  

**Example query**:
```bash
product:Apache country:TR # Apache servers in Turkey
```

## Contributing / Katkıda bulunma
We welcome contributions! To contribute:
- Fork the repository (`git clone`).  
- Create a branch (`git checkout -b feature/new-feature`).  
- Commit changes with clear, descriptive messages.  
- Push to your fork (`git push origin feature/new-feature`).  
- Open a pull request with a detailed description.  

Follow our code standards (e.g., PEP 8 for Python).  
Kodlama standartlarını takip edin (örneğin, Python için PEP 8).  

## License / Lisans
Licensed under the [MIT License](LICENSE).  
[MIT Lisansı](LICENSE) altında lisanslanmıştır.  

## Acknowledgements / Teşekkürler
Thanks to:
- **[Shodan.io](https://shodan.io)**: For providing a robust API and detailed documentation.  
  **[Shodan.io](https://shodan.io)**: Sağlam bir API ve ayrıntılı dokümantasyon için.  
- **İstinye University Penetration Testing Course**: For inspiring this project and fostering cybersecurity education.  
  **İstinye Üniversitesi Sızma Testi Dersi**: Bu projeye ilham vererek ve siber güvenlik eğitimini desteklediği için.  
- **Python Community**: For open-source libraries like `shodan` that power this project.  
  **Python Topluluğu**: Bu projeyi güçlendiren `shodan` gibi açık kaynak kütüphaneler için.  

## Contact / İletişim  
**Project Maintainer**: **Furkan Dinçer** - [hi@furkandincer.com](mailto:hi@furkandincer.com)  
**Bug Reports**: Open an issue at [github.com](https://github.com/frkndncr/shodan-device-scanner.git/issues)  
**Proje Sorumlusu**: **Furkan Dinçer** - [hi@furkandincer.com](mailto:hi@furkandincer.com)  
**Hata Bildirimi**: [github.com](https://github.com/frkndncr/shodan-device-scanner.git/issues) adresinde sorun bildirin  

Commit Date: **May 29, 2025**
