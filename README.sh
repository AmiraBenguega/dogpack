#!/bin/bash

# Help mesajı
help_message() {
    echo "Bu script, gerekli Python kütüphanelerini kontrol eder ve eksik olanları yükler."
    echo "Ardından dogpack.py dosyasını çalıştırır."
    echo "Kullanım: ./setup.sh"
}

# Kullanıcıya yardım mesajı göster
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    help_message
    exit 0
fi

# Gerekli kütüphaneler listesi
REQUIRED_PACKAGES=("requests" "python-whois" "geoip2" "dnspython" "argparse" "dnsresolver" "sublist3r" "builtwith" "selenium" "webdriver-manager" "beautifulsoup4" "waybackpy" "dnspython")

# Kütüphanelerin yüklü olup olmadığını kontrol et
check_and_install() {
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! pip show "$package" > /dev/null 2>&1; then
            echo "$package kütüphanesi yüklü değil. Yükleniyor..."
            pip install "$package"
        fi
    done
}

# GeoLite2-City.mmdb dosyasının mevcut olup olmadığını kontrol et
check_and_download_geoip() {
    if [ ! -f "GeoLite2-City.mmdb" ]; then
        echo "GeoLite2-City.mmdb dosyası bulunamadı. Dosya indiriliyor..."
        wget -O GeoLite2-City.mmdb "https://drive.google.com/uc?export=download&id=1tef6NTwJBicVxgDAq2OKKA178pwy-hiU"
    else
        echo "GeoLite2-City.mmdb dosyası mevcut."
    fi
}

# Kütüphane kontrolü ve yükleme işlemi
echo "Gerekli kütüphanelerin kontrolü ve yüklenmesi başlıyor..."
check_and_install

# GeoLite2-City.mmdb dosyasının kontrolü ve indirilmesi
check_and_download_geoip

# dogpack.py dosyasını çalıştır
echo "dogpack.py dosyasını çalıştırıyor..."
python dogpack.py --help
