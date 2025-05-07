![](https://github.com/erogluyusuf/dogpack/blob/main/dogpack.png)

# Dogpack.py - Bilgi Toplama ve Güvenlik Analiz Aracı

Dogpack.py, web sitelerindeki çeşitli güvenlik açıklarını taramak ve bilgi toplamak için kullanılan bir Python tabanlı araçtır. Web sitelerinin durumunu kontrol etmek, IP adresi, DNS kayıtları, SSL sertifikaları, portlar ve daha fazlasını analiz etmek için kullanılabilir.

## Özellikler

- **IP Adresi Al:** Web sitesinin IP adresini alır.
- **DNS Kayıtları:** Web sitesinin DNS kayıtlarını alır.
- **Whois Bilgileri:** Web sitesinin Whois bilgilerini alır.
- **Coğrafi Konum:** IP adresinin coğrafi konumunu alır.
- **Web Durumu Kontrolü:** Web sitesinin erişilebilirliğini kontrol eder.
- **Port Taraması:** Belirli portlar üzerinde tarama yapar.
- **SSL Sertifikası Kontrolü:** SSL sertifikasının geçerliliğini kontrol eder.
- **Web Sunucu Tespiti:** Web sunucusunun türünü tespit eder.
- **XSS Testi:** XSS açıklarını kontrol eder.
- **HTTP Başlıkları:** Web sitesinin HTTP başlıklarını kontrol eder.
- **Subdomain Taraması:** Alt domain taraması yapar.
- **Teknoloji Tespiti:** Web teknolojilerini tespit eder.
- **Dizin Tarama:** Web sitesinin dizinlerini tarar.
- **Crawl (Tarama):** Web sitesini tarar ve iç bağlantıları listeler.
- **E-posta Bulma:** Web sitesinde e-posta adreslerini bulur.
- **Wayback Machine Snapshotları:** Wayback Machine anlık görüntülerini alır.
- **SQL Injection Testi:** SQL injection açıklarını test eder.
- **CSRF Testi:** CSRF açıklarını test eder.
- **Open Redirect Testi:** Open Redirect açıklarını test eder.
- **Cookie Hijacking Kontrolü:** Cookie hijacking açıklarını kontrol eder.
- **Rate Limiting Testi:** Rate limiting açıklarını test eder.
- **DNS Zone Transferi:** DNS zone transferi açıklarını kontrol eder.
- **Sitemap Kontrolü:** sitemap.xml dosyasını kontrol eder ve analiz eder.
- **robots.txt Kontrolü:** robots.txt dosyasını kontrol eder.

## Kurulum

Aşağıdaki adımları takip ederek Dogpack.py aracını kurabilirsiniz:

1. Python 3.x yüklü olduğundan emin olun.
2. Dependent paketleri yükleyin:

```bash
pip install -r requirements.txt
```
Projeyi kullanmaya başlamak için aşağıdaki komutları kullanabilirsiniz:
```
python dogpack.py --get-ip
python dogpack.py --check-status
```
