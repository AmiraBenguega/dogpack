import time
import os
import argparse
import socket
import whois
import dns.resolver
import geoip2.database
import requests
import json
import ssl
import socket
import sublist3r
import subprocess
from builtwith import builtwith
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome import webdriver as chrome_webdriver
from webdriver_manager.chrome import ChromeDriverManager
import shutil
import re
from bs4 import BeautifulSoup
from waybackpy import WaybackMachineCDXServerAPI
import xml.etree.ElementTree as ET

# IP adresini al
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"IP Address: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"Unable to resolve domain: {domain}")
        return None

# DNS kayıtlarını al
def get_dns_records(domain):
    try:
        print(f"\nDNS Records for {domain}:")
        result = dns.resolver.resolve(domain, 'A')  # 'A' kayıtları, IP adresi çözümleme
        dns_records = []
        for ipval in result:
            dns_records.append(ipval.to_text())
            print(f"IP Address: {ipval.to_text()}")
        return dns_records
    except dns.resolver.NoAnswer:
        print("No DNS records found.")
        return []

# Whois bilgilerini al
def get_whois_info(domain):
    try:
        print(f"\nWhois Information for {domain}:")
        domain_info = whois.whois(domain)
        print(domain_info)
        return domain_info
    except Exception as e:
        print(f"Whois lookup failed: {e}")
        return None

# IP adresinin coğrafi konumunu al
def get_ip_geolocation(ip_address):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')  # GeoLite2 veritabanı dosyasını kullanman gerekiyor
        response = reader.city(ip_address)
        print(f"City: {response.city.name}")
        print(f"Country: {response.country.name}")
        print(f"Latitude: {response.location.latitude}, Longitude: {response.location.longitude}")
    except Exception as e:
        print(f"Geolocation lookup failed: {e}")

# Web sitesi durumu kontrol et
def check_website_status(url):
    try:
        response = requests.get(url)
        print(f"Website status for {url}: {response.status_code}")
        return response.status_code
    except requests.RequestException as e:
        print(f"Error checking website status: {e}")
        return None

# Port kontrolü fonksiyonu
def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # 1 saniye süre ile kontrol et
    result = sock.connect_ex((host, port))  # Portu kontrol et
    sock.close()
    if result == 0:
        return True  # Port açık
    else:
        return False  # Port kapalı

# SSL sertifikasını kontrol et
def check_ssl_cert(url):
    try:
        print(f"\nChecking SSL certificate for {url}")
        ssl_info = ssl.get_server_certificate((url, 443))
        print(f"SSL Certificate: {ssl_info}")
        return ssl_info
    except ssl.SSLError as e:
        print(f"SSL check failed: {e}")
        return None

# Web sunucusunun türünü tespit et
def detect_web_server(url):
    try:
        response = requests.head(url)
        server_info = response.headers.get('Server', 'Unknown')
        print(f"Web server type: {server_info}")
        return server_info
    except requests.RequestException as e:
        print(f"Error detecting web server: {e}")
        return None

# XSS açığını kontrol et
def check_xss_vulnerability(url):
    try:
        # Basit bir XSS kontrolü
        response = requests.get(url + "<script>alert('XSS')</script>")
        if "<script>alert('XSS')</script>" in response.text:
            print(f"Potential XSS vulnerability detected on {url}")
            return True
        else:
            print(f"No XSS vulnerability detected on {url}")
            return False
    except requests.RequestException as e:
        print(f"Error checking XSS vulnerability: {e}")
        return False

# HTTP başlıklarını kontrol et
def check_http_headers(url):
    try:
        response = requests.head(url)
        print(f"HTTP Headers for {url}:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
        return response.headers
    except requests.RequestException as e:
        print(f"Error checking HTTP headers: {e}")
        return None

# Kara liste kontrolü
def check_ip_blacklist(ip_address):
    # Basit bir kara liste kontrolü
    blacklisted_ips = ['192.168.1.1', '10.0.0.1']  # Örnek IP'ler
    if ip_address in blacklisted_ips:
        print(f"IP {ip_address} is blacklisted.")
        return True
    else:
        print(f"IP {ip_address} is not blacklisted.")
        return False

# Raporu JSON formatında kaydet
def save_report(domain, ip_address, dns_records, whois_info, ssl_info, server_info, xss_vuln, http_headers):
    report = {
        'Domain': domain,
        'IP Address': ip_address,
        'DNS Records': dns_records,
        'Whois Info': str(whois_info),
        'SSL Info': ssl_info,
        'Web Server Info': server_info,
        'XSS Vulnerability': xss_vuln,
        'HTTP Headers': http_headers
    }
    with open(f'{domain}_report.json', 'w') as json_file:
        json.dump(report, json_file, indent=4)
    print(f"\nReport saved as {domain}_report.json")




def find_subdomains(domain):
    print(f"Finding subdomains for {domain}...")
    try:
        # sublist3r komut satırı aracını subprocess ile çalıştırıyoruz
        result = subprocess.run(['sublist3r', '-d', domain, '-o', 'subdomains.txt'], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Subdomains found for {domain}:")
            # subdomains.txt dosyasını oku ve subdomain'leri ekrana yazdır
            with open('subdomains.txt', 'r') as file:
                subdomains = file.readlines()
                if subdomains:
                    for subdomain in subdomains:
                        print(subdomain.strip())
                else:
                    print("No subdomains found.")
        else:
            print(f"Error during subdomain search: {result.stderr}")
    except Exception as e:
        print(f"An error occurred: {e}")

def detect_technologies(url):
    try:
        tech = builtwith(url)
        print("\nKullanılan Teknolojiler:")
        for key, values in tech.items():
            print(f"{key}: {', '.join(values)}")
        return tech
    except Exception as e:
        print(f"Teknoloji tespiti başarısız: {e}")
        return None

def directory_scan(url):
    print("\nDizin taraması başlatıldı...")
    wordlist = ['admin', 'login', 'dashboard', 'uploads', 'config', 'backup', 'panel']
    for word in wordlist:
        full_url = f"{url.rstrip('/')}/{word}"
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200:
                print(f"[+] Bulundu: {full_url}")
            elif response.status_code == 403:
                print(f"[!] Erişim Engellendi (403): {full_url}")
        except requests.RequestException:
            pass



# Sayfayı derinlemesine tarar, iç bağlantıları listeler
def crawl_page(url):
    try:
        print(f"\nCrawling page: {url}")
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            link = a_tag['href']
            if link.startswith('http'):
                links.add(link)
        print(f"Found {len(links)} links:")
        for link in links:
            print(link)
        return links
    except requests.RequestException as e:
        print(f"Error crawling page: {e}")
        return []

# Sayfa içinden e-posta adreslerini toplar
def find_emails(url):
    try:
        print(f"\nFinding emails on: {url}")
        response = requests.get(url)
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text))
        print(f"Found {len(emails)} emails:")
        for email in emails:
            print(email)
        return emails
    except requests.RequestException as e:
        print(f"Error finding emails: {e}")
        return []



def get_wayback_snapshots(domain):
    try:
        print(f"\nGetting Wayback Machine snapshots for {domain}")
        wayback = WaybackMachineCDXServerAPI(domain)
        snapshots = list(wayback.snapshots())  # generator → liste
        if snapshots:
            print(f"Found {len(snapshots)} snapshots:")
            for snapshot in snapshots:
                print(f"Snapshot URL: {snapshot.archive_url}")  # ← doğru alan
        else:
            print("No snapshots found.")
    except Exception as e:
        print(f"Error getting Wayback snapshots: {e}")

# SQL Injection Testi
def sqli_test(url):
    print(f"Testing SQL Injection on {url}")
    payloads = ["' OR 1=1 --", "' OR 'a'='a"]
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"  # id parametresi örnek olarak kullanıldı.
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or response.status_code == 500:
                print(f"Potential SQL Injection found with payload: {payload}")
            else:
                print(f"No SQL Injection found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")

# CSRF Testi
def csrf_test(url):
    print(f"Testing CSRF vulnerability on {url}")
    # Basit bir CSRF test payload'ı eklenebilir
    payload = "<script>alert('CSRF')</script>"
    response = requests.post(url, data={'csrf_test': payload})
    if payload in response.text:
        print("Potential CSRF vulnerability detected.")
    else:
        print("No CSRF vulnerability detected.")

# Open Redirect Testi
def open_redirect_test(url):
    print(f"Testing Open Redirect vulnerability on {url}")
    # Basit bir open redirect test payload'ı eklenebilir
    payload = "http://evil.com"
    test_url = f"{url}?redirect={payload}"
    response = requests.get(test_url)
    if payload in response.text:
        print(f"Open Redirect found with payload: {payload}")
    else:
        print("No Open Redirect vulnerability found.")

def rate_limit_test(url):
    # Eğer URL şemasız ise, http:// ekleyelim
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    for _ in range(10):  # 10 istek göndereceğiz
        response = requests.get(url)
        print(f"Status Code: {response.status_code} for {url}")
        time.sleep(0.5)  # Rate-limiting test için 0.5 saniye bekleyelim


def dns_zone_transfer_test(domain):
    try:
        resolver = dns.resolver.Resolver()
        zone = resolver.resolve(domain, 'SOA')
        print(f"DNS Zone Transfer is allowed for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"DNS Zone Transfer is NOT allowed for {domain}")

def cookie_hijack_test(url):
    # URL'de şema (http/https) olup olmadığını kontrol et
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    response = requests.get(url)
    cookies = response.cookies

    for cookie in cookies:
        # Cookie'nin HttpOnly ve Secure flag'lerini kontrol et
        if not cookie.has_nonstandard_attr('HttpOnly') or not cookie.has_nonstandard_attr('Secure'):
            print(f"Potential Cookie Hijacking vulnerability in cookie: {cookie.name}")
        else:
            print(f"Cookie {cookie.name} is secure.")

def check_sitemap(domain):
    sitemap_url = f"http://{domain}/sitemap.xml"
    try:
        response = requests.get(sitemap_url)
        response.raise_for_status()  # HTTP errorları kontrol et
        print(f"Sitemap.xml found for {domain}. Here's the content:")
        print(response.text)  # Sitemap içeriğini yazdır
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching sitemap for {domain}: {e}")

def check_robots_txt(domain):
    robots_url = f"http://{domain}/robots.txt"
    try:
        response = requests.get(robots_url)
        response.raise_for_status()
        
        # Robots.txt içeriği
        print(f"Robots.txt for {domain}:")
        print(response.text)

        # Robots.txt içinde sitemap bilgisi arayalım
        if 'Sitemap:' in response.text:
            print("\nSitemap found in robots.txt:")
            sitemap_urls = [line for line in response.text.split('\n') if 'Sitemap:' in line]
            for url in sitemap_urls:
                print(url)
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching robots.txt for {domain}: {e}")

def check_http_methods(domain):
    url = f"http://{domain}"
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    
    supported_methods = []
    
    for method in methods:
        try:
            response = requests.request(method, url)
            if response.status_code != 405:  # 405 Method Not Allowed hatası, desteklenmeyen metodlar için döner
                supported_methods.append(method)
        except requests.exceptions.RequestException as e:
            print(f"Error with method {method} on {domain}: {e}")
    if supported_methods:
        print(f"Active HTTP methods for {domain}: {', '.join(supported_methods)}")
    else:
        print(f"No supported HTTP methods detected for {domain}.")



def directory_traversal_test(domain):
    # Test edilecek dizin yolları (Linux ve Windows sistemleri için)
    directories = [
    # Linux sistemleri için test dizinleri
    "../../../../etc/passwd",  # Linux - Kullanıcı bilgileri
    "../../../../etc/shadow",  # Linux - Parola dosyası
    "../../../../etc/hosts",  # Linux - Yerel ağ yapılandırması
    "../../../../etc/mysql/",  # Linux - MySQL yapılandırma dosyaları
    "../../../../etc/apache2/",  # Linux - Apache yapılandırma dosyaları
    "../../../../etc/nginx/",  # Linux - Nginx yapılandırma dosyaları
    "../../../../var/www/html",  # Linux - Web sunucusunun kök dizini
    "../../../../var/log",  # Linux - Sistem log dosyaları
    "../../../../home/user/.ssh/id_rsa",  # Linux - SSH anahtarları
    "../../../../home/user/.bash_history",  # Linux - Bash geçmişi
    "../../../../wp-config.php",  # Linux - WordPress yapılandırma dosyası
    "../../../../config/config.php",  # Linux - Konfigürasyon dosyası
    "../../../../backup/backup.sql",  # Linux - Yedek dosyası
    "../../../../tmp/file.txt",  # Linux - Geçici dosya
    "../../../../bin",  # Linux - Çalıştırılabilir dosyalar
    "../../../../usr/bin",  # Linux - Kullanıcı komutları
    "../../../../dev",  # Linux - Sistem aygıt dosyaları
    "../../../../proc",  # Linux - Kernel ve işlem bilgileri
    "../../../../home/user/.git/",  # Linux - Git deposu ve konfigürasyonu
    "../../../../var/spool/mail",  # Linux - Kullanıcı e-posta dosyaları
    "../../../../var/cache/",  # Linux - Web ve sistem önbellek dosyaları
    "../../../../var/tmp/",  # Linux - Geçici dosyalar
    "../../../../usr/local/bin/",  # Linux - Kullanıcı komut dosyaları
    "../../../../usr/local/etc/",  # Linux - Kullanıcı yapılandırma dosyaları

    # Windows sistemleri için test dizinleri
    "C:/Windows/System32",  # Windows - Sistem dosyaları
    "C:/Windows/win.ini",  # Windows - Başlangıç konfigürasyonu
    "C:/Users",  # Windows - Kullanıcı dizinleri
    "C:/Program Files",  # Windows - Program dizinleri
    "C:/Temp",  # Windows - Geçici dosyalar
    "C:/Users/<user>/AppData/Roaming/",  # Windows - Kullanıcı verileri (Roaming)
    "C:/Users/<user>/AppData/Local/",  # Windows - Kullanıcı verileri (Yerel)
    "C:/ProgramData/",  # Windows - Program veri dosyaları
    "C:/Windows/SoftwareDistribution/",  # Windows - Windows güncellemeleri
    "C:/Windows/WinSxS/",  # Windows - Windows bileşen dosyaları
    "C:/Windows/System32/config/",  # Windows - Windows yapılandırma dosyaları

    # Web Uygulama Dosyaları
    "/admin/",  # Web uygulaması - Admin paneli
    "/config/",  # Web uygulaması - Konfigürasyon dosyaları
    "/uploads/",  # Web uygulaması - Yüklenen dosyalar
    "/logs/",  # Web uygulaması - Web sunucusu log dosyaları
    "/backup/",  # Web uygulaması - Yedek dosyaları
    "/private/",  # Web uygulaması - Özel dosyalar
    "/wp-config.php",  # Web uygulaması - WordPress yapılandırma dosyası
    "/database.db",  # Web uygulaması - Veritabanı dosyası
    "/cgi-bin/",  # Web uygulaması - CGI betikleri
    "/admin/config.php",  # Web uygulaması - Admin yapılandırma dosyası
    "/admin/db_config.php",  # Web uygulaması - Veritabanı yapılandırma dosyası
    "/private/.htpasswd",  # Web uygulaması - .htpasswd dosyası (kimlik doğrulama)
    "/uploads/user_uploads/",  # Web uygulaması - Kullanıcı yüklemeleri
    "/temp/sessions/",  # Web uygulaması - Oturum dosyaları
    "/public_html/",  # Web uygulaması - Web sunucusunun kök dizini
    "/var/www/vhosts/",  # Web uygulaması - Çoklu web barındırma dizini
    "/config/.env",  # Web uygulaması - Çevre değişkenleri dosyası

    # Diğer uygulama ve sistem dosyaları
    "/home/user/.docker/",  # Docker yapılandırma dosyaları
    "/var/lib/docker/",  # Docker veritabanı ve konteyner dosyaları
    "/opt/",  # Uygulama dizini
    "/var/www/html/wp-content/",  # WordPress içerik dosyaları
    "/etc/nginx/",  # Nginx yapılandırma dosyaları
    "/etc/apache2/",  # Apache yapılandırma dosyaları
    "/var/www/backup/",  # Web uygulaması yedek dosyaları
]

    
    # Her bir dizin için test yap
    for directory in directories:
        test_url = f"http://{domain}/{directory}"
        print(f"Testing directory traversal on {test_url}")
        
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"Potential vulnerability found for {test_url}")
            else:
                print(f"No vulnerability found for {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {test_url}: {e}")

        

def clickjacking_protection_check(url):
    response = requests.head(url)
    if 'X-Frame-Options' not in response.headers:
        print(f"No Clickjacking protection for {url}")
    else:
        print(f"Clickjacking protection present for {url}: {response.headers['X-Frame-Options']}")






# Ana fonksiyon
def main():
    # Argparse ile parametreleri tanımla
    parser = argparse.ArgumentParser(description='Web güvenlik tarayıcı aracınız')
    
    # Domain adı parametresi zorunlu
    parser.add_argument('domain', type=str, help='Domain adını girin.')
    
    # Opsiyonel parametreler
    parser.add_argument('--get-ip', action='store_true', help='IP adresini al.')
    parser.add_argument('--get-dns', action='store_true', help='DNS kayıtlarını al.')
    parser.add_argument('--get-whois', action='store_true', help='Whois bilgilerini al.')
    parser.add_argument('--get-geolocation', action='store_true', help='IP adresinin coğrafi konumunu al.')
    parser.add_argument('--check-status', action='store_true', help='Web sitesinin durumunu kontrol et.')
    parser.add_argument('--check-port', type=str, help='Port taraması yapmak için port numaralarını virgülle ayırarak girin.')
    parser.add_argument('--check-ssl', action='store_true', help='SSL sertifikasını kontrol et.')
    parser.add_argument('--webserver', action='store_true', help='Web sunucusunun türünü tespit et.')
    parser.add_argument('--xss', action='store_true', help='XSS açıklarını kontrol et.')
    parser.add_argument('--headers', action='store_true', help='HTTP başlıklarını kontrol et.')
    parser.add_argument('--save-report', action='store_true', help='Raporu JSON formatında kaydet.')
    parser.add_argument('--find-subdomains', action='store_true', help='Subdomain taraması yap.')
    parser.add_argument('--tech-detect', action='store_true', help='Web teknolojilerini tespit et.')
    parser.add_argument('--dirscan', action='store_true', help='Dizin taraması yap.')
#    parser.add_argument('--screenshot', action='store_true', help='Web sitesinin ekran görüntüsünü al.')
    parser.add_argument('--crawl', action='store_true', help='Crawl the website and list internal links.')
    parser.add_argument('--emails', action='store_true', help='Find emails on the website.')
    parser.add_argument('--wayback', action='store_true', help='Get Wayback Machine snapshots.')
    parser.add_argument('--sqli', action='store_true', help='Test for SQL injection vulnerabilities.')
    parser.add_argument('--csrf', action='store_true', help='Test for CSRF vulnerabilities.')
    parser.add_argument('--open-redirect', action='store_true', help='Test for Open Redirect vulnerabilities.')
    parser.add_argument("--cookie-hijack", help="Check for cookie hijacking vulnerabilities", action="store_true")
    parser.add_argument("--rate-limit", help="Test rate limiting vulnerabilities", action="store_true")
    parser.add_argument("--dns-zone-transfer", help="Check for DNS zone transfer vulnerabilities", action="store_true")
    parser.add_argument('--sitemap-check', help="Check and analyze sitemap.xml", action="store_true")
    parser.add_argument('--check-robots', help="Check robots.txt for sitemap URL", action="store_true")
    parser.add_argument('--http-methods', help="Check active HTTP methods", action="store_true")
    parser.add_argument('--directory-traversal', help="Check for directory traversal vulnerabilities", action="store_true")
    parser.add_argument('--clickjacking', help="Check for clickjacking protection", action="store_true")


    # Parametreleri al
    args = parser.parse_args()
    domain = args.domain  # Kullanıcıdan alınan domain
    
    # IP adresini al
    ip_address = None
    if args.get_ip:
        ip_address = get_ip_address(domain)
    
    # DNS kayıtlarını al
    dns_records = []
    if args.get_dns:
        dns_records = get_dns_records(domain)
    
    # Whois bilgilerini al
    whois_info = None
    if args.get_whois:
        whois_info = get_whois_info(domain)
    
    # IP coğrafi konumunu al
    if ip_address and args.get_geolocation:
        get_ip_geolocation(ip_address)
    
    # Web sitesi durumunu kontrol et
    if args.check_status:
        check_website_status(f"http://{domain}")
    
    # Port taraması yap
    if args.check_port:
        ports = [int(port.strip()) for port in args.check_port.split(',')]
        print(f"\nChecking ports for {domain}: {ports}")
        for port in ports:
            if check_port(domain, port):
                print(f"Port {port} açık.")
            else:
                print(f"Port {port} kapalı.")
    
    # SSL sertifikasını kontrol et
    ssl_info = None
    if args.check_ssl:
        ssl_info = check_ssl_cert(domain)
    
    # Web sunucusunun türünü tespit et
    server_info = None
    if args.webserver:
        server_info = detect_web_server(domain)
    
    # XSS açıklarını kontrol et
    xss_vuln = None
    if args.xss:
        xss_vuln = check_xss_vulnerability(f"http://{domain}")
    
    # HTTP başlıklarını kontrol et
    http_headers = None
    if args.headers:
        http_headers = check_http_headers(f"http://{domain}")

    if args.tech_detect:
        detect_technologies(f"http://{domain}")
    
    if args.dirscan:
        directory_scan(f"http://{domain}")

    # if args.screenshot:
    #    take_screenshot(f"http://{domain}", domain)

    # Crawl the page
    if args.crawl:
        crawl_page(f"http://{domain}")

    # Find emails
    if args.emails:
        find_emails(f"http://{domain}")
    
    # Get Wayback snapshots
    if args.wayback:
        get_wayback_snapshots(domain)

    # Subdomain taraması yap
    if args.find_subdomains:
        find_subdomains(domain)

    if args.sqli:
        sqli_test(f"http://{domain}")
    if args.csrf:
        csrf_test(f"http://{domain}")
    if args.open_redirect:
        open_redirect_test(f"http://{domain}")
    if args.cookie_hijack:
        cookie_hijack_test(args.domain)
    
    if args.rate_limit:
        rate_limit_test(args.domain)

    if args.dns_zone_transfer:
        dns_zone_transfer_test(args.domain)


    if args.sitemap_check:
        check_sitemap(domain)
    
    if args.check_robots:
        check_robots_txt(domain)

    if args.http_methods:
        check_http_methods(domain)
    
    if args.directory_traversal:
        directory_traversal_test(domain)





    # Raporu JSON formatında kaydet
    if args.save_report:
        save_report(domain, ip_address, dns_records, whois_info, ssl_info, server_info, xss_vuln, http_headers)

if __name__ == "__main__":
    main()
