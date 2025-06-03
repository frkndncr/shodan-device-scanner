# Development Steps / Geliştirme Adımları

This document outlines the development steps for the Shodan Device Scanner project, ensuring a structured approach to building the tool.  
Bu belge, Shodan Device Scanner projesinin geliştirme adımlarını özetler ve aracı yapılandırmada düzenli bir yaklaşım sağlar.

## Step 1: Project Setup / Proje Kurulumu
- Initialize a GitHub repository at `https://github.com/frkndncr/shodan-device-scanner.git`.  
  GitHub deposunu `https://github.com/frkndncr/shodan-device-scanner.git` adresinde başlatma.  
- Create the project structure with `src/`, `researchs/`, `struct/`, and `outputs/` directories.  
  `src/`, `researchs/`, `struct/`, ve `outputs/` dizinleriyle proje yapısını oluşturma.  
- Set up a Python virtual environment and install dependencies (`shodan==1.31.0`).  
  Python sanal ortamını kurma ve bağımlılıkları yükleme (`shodan==1.31.0`).

## Step 2: Shodan API Integration / Shodan API Entegrasyonu
- Obtain a Shodan API key from [shodan.io](https://www.shodan.io).  
  [shodan.io](https://www.shodan.io) adresinden Shodan API anahtarı alma.  
- Implement `src/main.py` to perform device scanning using Shodan API filters (e.g., `product:Apache country:TR`).  
  Shodan API filtrelerini kullanarak cihaz taraması yapmak için `src/main.py`'yi uygulama.  
- Save scan results as JSON files in the `outputs/` directory.  
  Tarama sonuçlarını `outputs/` dizininde JSON dosyaları olarak kaydetme.

## Step 3: Research and Documentation / Araştırma ve Dokümantasyon
- Conduct research on Shodan API, IoT security trends, and advanced filters.  
  Shodan API, IoT güvenlik trendleri ve gelişmiş filtreler üzerine araştırma yapma.  
- Document findings in `researchs/` directory with files like `shodan-api.md`, `iot-security.md`, and `advanced-filters.md`.  
  Bulguları `researchs/` dizininde `shodan-api.md`, `iot-security.md` ve `advanced-filters.md` gibi dosyalarla belgeleme.  
- Update `README.md`, `ROADMAP.md`, `PROMPTS.md`, and `struct/structure.md` for comprehensive documentation.  
  Kapsamlı dokümantasyon için `README.md`, `ROADMAP.md`, `PROMPTS.md` ve `struct/structure.md` dosyalarını güncelleme.

## Step 4: Future Enhancements / Gelecek Geliştirmeler
- Plan enhancements like a web interface, data visualization, and database integration (see `ROADMAP.md`).  
  Web arayüzü, veri görselleştirme ve veritabanı entegrasyonu gibi geliştirmeleri planlama (bakınız `ROADMAP.md`).  
- Test the tool with various Shodan queries to ensure robustness.  
  Aracın sağlamlığını sağlamak için çeşitli Shodan sorgularıyla test etme.  
- Prepare a final report summarizing findings and potential applications in penetration testing.  
  Sızma testindeki bulguları ve potansiyel uygulamaları özetleyen bir nihai rapor hazırlama.

Commit Date: May 29, 2025
