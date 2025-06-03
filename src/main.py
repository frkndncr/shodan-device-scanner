import shodan
import json
from datetime import datetime
import sys
import os

# Shodan API anahtarınızı buraya ekleyin
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

def search_shodan(query, api_key):
    """
    Shodan API ile verilen sorguya göre cihaz arar ve sonuçları döndürür.
    """
    try:
        # Shodan API istemcisini başlat
        api = shodan.Shodan(api_key)
        
        # Sorguyu çalıştır
        results = api.search(query)
        
        # Sonuçları işlemek için liste
        output = []
        
        for result in results['matches']:
            device_info = {
                'ip': result['ip_str'],
                'port': result['port'],
                'os': result.get('os', 'Bilinmiyor'),
                'org': result.get('org', 'Bilinmiyor'),
                'location': result.get('location', {}).get('country_name', 'Bilinmiyor'),
                'timestamp': result.get('timestamp', 'Bilinmiyor'),
            }
            output.append(device_info)
        
        return output
    
    except shodan.APIError as e:
        print(f"Hata: {e}")
        return []

def save_results(results, filename):
    """
    Sonuçları JSON formatında dosyaya kaydeder.
    """
    os.makedirs('outputs', exist_ok=True)  # outputs klasörünü oluştur
    filepath = os.path.join('outputs', filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"Sonuçlar {filepath} dosyasına kaydedildi.")

def main():
    # Örnek sorgu: Türkiye'deki Apache sunucuları
    query = 'product:Apache country:TR'
    
    # Shodan'dan sonuçları al
    results = search_shodan(query, SHODAN_API_KEY)
    
    if results:
        # Sonuçları ekrana yazdır
        print(f"Toplam {len(results)} cihaz bulundu:")
        for device in results:
            print(f"IP: {device['ip']}, Port: {device['port']}, OS: {device['os']}, "
                  f"Organizasyon: {device['org']}, Ülke: {device['location']}")
        
        # Sonuçları dosyaya kaydet
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"shodan_results_{timestamp}.json"
        save_results(results, filename)
    else:
        print("Hiçbir cihaz bulunamadı veya API hatası oluştu.")

if __name__ == "__main__":
    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
        print("Lütfen SHODAN_API_KEY değişkenine geçerli bir API anahtarı girin.")
        sys.exit(1)
    main()
