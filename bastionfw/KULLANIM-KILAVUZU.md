Markdown

# BastionFW Müşteri Kurulum ve Kullanım Kılavuzu

Bu kılavuz, BastionFW güvenlik duvarı sistemini kendi sunucunuza Docker kullanarak en hızlı ve sorunsuz şekilde kurmanız için hazırlanmıştır.

---

## 1. Ön Gereksinimler
Kuruluma başlamadan önce sunucunuzda aşağıdaki araçların kurulu olduğundan emin olun:
- Docker
- Docker Compose

---

## 2. Hızlı Kurulum Adımları

### 1. Adım: Proje Klasörüne Giriş Yapın
Size iletilen BastionFW kurulum paketini sunucunuza çıkartın ve terminal üzerinden ilgili klasörün içine girin:
```bash
cd bastionfw

2. Adım: Hedef Web Sitesini Tanımlayın

Sistemin koruyacağı web sitesini ayarlamak için docker-compose.yml dosyasını bir metin düzenleyici ile açın ve TARGET_URL değişkenini kendi sitenizin adresiyle güncelleyin:
YAML

environment:
  - TARGET_URL=[https://sizin-websiteniz.com](https://sizin-websiteniz.com)

3. Adım: Sistemi Tek Komutla Başlatın

Terminalde aşağıdaki komutu çalıştırarak Docker konteynerini derleyin ve arka planda çalışır duruma getirin:
Bash

docker compose up --build -d

3. Web Arayüzü (Dashboard) Kullanımı

Sistem başarıyla ayağa kalktıktan sonra yönetim paneline tarayıcınız üzerinden şu adresle bağlanabilirsiniz:
Plaintext

http://<sunucu-ip-adresiniz>:8080

Panel üzerinden anlık olarak takip edebileceğiniz özellikler:

    Tespit edilen tehditler ve güvenlik alarmları

    Canlı log akışı ve işlenen veri durumu

    Firewall koruma ve sistem durum metrikleri

4. Yönetim ve Kontrol Komutları

    Çalışma Durumunu Kontrol Etme:
    Bash

    docker ps

    Canlı Logları İnceleme:
    Bash

    docker logs --tail 50 -f bastionfw-engine

    Sistemi Durdurma / Kapatma:
    Bash

    docker compose down

5. Sık Karşılaşılan Sorunlar
Panale Tarayıcıdan Erişilemiyor

    Sunucunuzun güvenlik duvarında (firewall) veya bulut sağlayıcınızın ağ ayarlarında 8080 portunun gelen bağlantılara açık olduğundan emin olun.

    http://127.0.0.1:8080 adresi yalnızca sunucunun kendisinden erişirken geçerlidir; dışarıdan bağlanmak için sunucunun gerçek IP adresi kullanılmalıdır.

Konteyner Başlamıyor veya Hata Veriyor

    Logları detaylı incelemek için docker logs bastionfw-engine komutunu çalıştırarak hata detayını kontrol edebilirsiniz.
