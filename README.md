# BastionFW — Linux Güvenlik Platformu

> Bir sunucunun loglarını okuyup saldırı girişimlerini **otomatik olarak tespit eden**,
> gerektiğinde saldırganın IP'sini **geçici olarak engelleyen**, bunu bir web
> panelinde ve Prometheus metrikleriyle gösteren savunma aracı.

Sürüm: **3.2.2** · Python 3.11+ · MIT lisanslı

---

## İçindekiler

1. [Bu araç ne işe yarar?](#1-bu-araç-ne-işe-yarar)
2. [Ne YAPmaz?](#2-ne-yapmaz)
3. [Nasıl çalışır? (5 dakikalık zihinsel model)](#3-nasıl-çalışır-5-dakikalık-zihinsel-model)
4. [Terimler sözlüğü](#4-terimler-sözlüğü)
5. [Kurulum — Yöntem A: Docker (önerilen)](#5-kurulum--yöntem-a-docker-önerilen)
6. [Kurulum — Yöntem B: Docker'sız, elle (host'a kurulum)](#6-kurulum--yöntem-b-dockersız-elle-hosta-kurulum)
7. [Yeni başlayanlar için: ilk 10 dakika](#7-yeni-başlayanlar-için-ilk-10-dakika)
8. [Yapılandırma rehberi](#8-yapılandırma-rehberi)
9. [Panel ve API uçları](#9-panel-ve-api-uçları)
10. [Saldırıları gerçekten engellemek (dry-run → gerçek)](#10-saldırıları-gerçekten-engellemek-dry-run--gerçek)
11. [WAF (Coraza + OWASP CRS)](#11-waf-coraza--owasp-crs)
12. [Sık kullanılan komutlar](#12-sık-kullanılan-komutlar)
13. [Sorun giderme](#13-sorun-giderme)
14. [Geliştirici bilgisi](#14-geliştirici-bilgisi)
15. [Depo yapısı](#15-depo-yapısı)
16. [Güvenlik duruşu](#16-güvenlik-duruşu)

---

## 1. Bu araç ne işe yarar?

Bir Linux sunucusunu ele geçirmeye çalışan insanlar genellikle **SSH parolasını
deneyerek** veya **web sitendeki formlara SQL enjeksiyonu göndererek** saldırır.
Bu denemelerin tamamı sunucunda **bir yere loglanır**:

- `/var/log/auth.log` → "Failed password for root from 1.2.3.4"
- `/var/log/nginx/access.log` → "GET /index.php?id=1' OR '1'='1"

Normalde bu loglar kimse tarafından canlı izlenmez. Birisi SSH parolanızı 10.000 kez
denediğinde bile, sisteminiz log'a bir satır yazar ve olay orada kalır.

**BastionFW bu logları canlı okur ve şunu yapar:**

| Adım | Ne olur |
|---|---|
| 1. **İzleme** | Log dosyalarını saniyede birkaç kez okur (tail). Yeni satır yoksa boşta durur, kaynak harcamaz. |
| 2. **Analiz** | Her satırı ayrıştırır: bu bir SSH başarısız girişimi mi, bir web saldırısı mı? |
| 3. **Tespit** | Aynı IP'den pencere içinde (varsayılan 60 sn) 8 başarısız SSH denemesi → **brute-force tespit edildi**. |
| 4. **Karar** | Varsayılan olarak sadece **kaydeder ve uyarır** (dry-run modu). |
| 5. **Engelleme** | Mod etkinleştirilirse o IP'yi sunucunun **güvenlik duvarına** geçici olarak ekler (varsayılan 24 saat). |
| 6. **Görünürlük** | Web paneli, Prometheus metrikleri, webhook bildirimleri. |

Kısacası: **saldırı olurken fark edersiniz, saldırı sürerken engellenir, sonra ne
olduğunu raporlayabilirsiniz.**

### Kimler için?

- Tek bir sunucunun güvenliğini kendi elleriyle yönetmek istenen sistem yöneticileri
- Kaba kuvvet (brute-force) saldırısı alan ve bunu fark etmek isteyenler
- Docker + Prometheus + Grafana altyapısı olan küçük/orta ekipler
- Güvenlik araçlarını öğrenmek isteyen geliştiriciler

### Hangi durumlarda kullanılmaz?

- **Çok sunuculu büyük altyapılar için tek başına yeterli değildir.** Sunucu başına
  bir ajan kurarsınız; merkezî politika ve olay veri yolu bunun *üstüne* kurulur.
  (Bkz. `bastionfw/README.md` → "Design boundaries".)
- **Kötü niyetli kullanım için değildir.** Bu bir saldırı aracı değil, savunma aracıdır.

---

## 2. Ne Yapmaz?

Dürüst olmak gerekirse, bu araç şunları **yapmaz**:

- ❌ **Logları geriye dönük taramaz.** Sadece çalıştıktan *sonra* gelen satırları görür.
  Dün gece olan saldırıyı bulmaz.
- ❌ **Saldırıyı durdurmaz, sadece IP'yi engeller.** Saldırgan aynı IP'den sürekli
  yeni bağlantı açan bir bot ağıysa, engelleme tek başına yetmez.
- ❌ **Kendi hatalarınızı bulmaz.** Yanlış yazılmış bir SSH parolasını "saldırı" sanmaz.
- ❌ **Bağımsız denetimden geçmemiştir.** Otomatik testler ve statik analiz var, ama
  profesyonel bir güvenlik firması tarafından denetlenmemiştir.
- ❌ **Varsayılan olarak hiçbir şeyi engellemez.** Güvenlik gereği ilk açılışta
  tamamen gözlem modundadır.

---

## 3. Nasıl çalışır? (5 dakikalık zihinsel model)

```
   ┌──────────────────────┐
   │  /var/log/auth.log   │
   │  /var/log/nginx/...  │        ① TAILER (tailer.py)
   │  WAF audit JSON      │  ───►  dosyayı sürekli okur, yeni satırları
   └──────────────────────┘        sıraya koyar (log rotasyonunu bilir)
                                   
   ┌──────────────────────┐
   │  Sınırlı kuyruk      │        ② PARSER (parsing.py)
   │  (queue_size: 50000) │  ───►  satırı IP + saldırı tipi + kanıta çevirir
   └──────────────────────┘
                                    
   ┌──────────────────────┐
   │  Tespit kuralları    │        ③ DETECTOR (detector.py)
   │  SSHBruteForceRule   │  ───►  "60 sn'de 8 hata" kuralı tetiklenir → olay
   │  WebAttackRule       │
   └──────────────────────┘
                 │
                 ▼
   ┌──────────────────────┐
   │  Güvenlik politikası │        ④ ORCHESTRATOR (firewall.py)
   │  whitelist kontrolü  │  ───►  "Bu IP engellenmeli mi?" sorusu.
   │  ban_seconds süresi   │        Özel/özel IP'ler her zaman reddedilir.
   └──────────────────────┘
                 │  (dry-run ise burada durur, sadece kaydeder)
                 ▼
   ┌──────────────────────┐
   │  nftables / iptables │        ⑤ SÜRÜCÜ (firewall.py)
   │  / ufw / firewalld   │  ───►  gerçek sistem güvenlik duvarına kural yazar
   └──────────────────────┘
                 
   ┌────────────────────────────────────┐
   │  PANEL (:8080)  METRİK (:9109)    │  ⑥ GÖRÜNÜRLÜK
   │  dashboard.py     /metrics         │     (dashboard.py, logger.py)
   │  WEBHOOK bildirimleri               │
   └────────────────────────────────────┘
```

**Kritik güvenlik kuralı:** 5. adıma giden bir IP adresi her zaman şu kontrollerden
geçer: gerçek ve geçerli bir IP mi, **herkese açık (public)** bir IP mi, beyaz
listede mi değil mi. Özel ağ adresleri (`10.x`, `192.168.x`, `127.0.0.1`) asla
engellenmez — yoksa kendi altyapınızı kapatırsınız.

---

## 4. Terimler sözlüğü

| Terim | Anlamı |
|---|---|
| **Log (kayıt dosyası)** | Sunucunun yaptığı her şeyi yazdığı metin dosyası. |
| **Tail** | Bir dosyanın sonunu okumak. BastionFW sürekli "tail" eder. |
| **IP adresi** | Bir cihazın internetteki kimliği, ör. `203.0.113.10`. |
| **Dry-run (kuru çalışma)** | Her şeyi yapar, gösterir, *ama sisteme dokunmaz*. Güvenli varsayılan. |
| **Ban (engelleme)** | Bir IP'nin sunucuya bağlanmasını firewall seviyesinde reddetmek. |
| **Whitelist (beyaz liste)** | Asla engellenmeyecek IP'ler. Kendi sunucunuz burada olmalı. |
| **nftables** | Modern Linux paket filtresi. BastionFW'nin tercih ettiği backend. |
| **WAF** | Web Application Firewall — sitenizin önünde duran, kötü web isteklerini eleyen katman. |
| **Prometheus** | Metrik toplayan izleme sistemi. BastionFW `/metrics` uç noktası verir. |
| **Webhook** | Bir olay olduğunda BastionFW'nin otomatik POST yaptığı adres (Slack/Discord/özel). |
| **hypothesis** | Rastgele girdilerle "fuzz" testi yapan Python kütüphanesi. |

---

## 5. Kurulum — Yöntem A: Docker (önerilen)

Bu yöntem **hiçbir şeyi kurmadan** çalışmanızı sağlar: Python, firewall, WAF hepsi
container içinde gelir.

### 5.1 Gereksinimler

Sadece şunlar gerekir:

- **Docker Engine** ve **Docker Compose v2**
  - Kontrol: `docker --version` ve `docker compose version`
- Boş bir **log dizini** (BastionFW'nin okuyacağı yer)
- ~500 MB disk alanı

> Docker Compose v2 `docker-compose` (tireli) değil, `docker compose` (boşluklu) yazımıdır.

### 5.2 Adım adım kurulum

**Adım 1 — Repoyu edinin**

```bash
git clone https://github.com/caganutkusaymaz1/BastionFW.git
cd BastionFW
```

> Zip olarak indirmek isterseniz:
> [BastionFW-v3.2.2.zip](https://raw.githubusercontent.com/caganutkusaymaz1/BastionFW/main/BastionFW-v3.2.2.zip)

**Adım 2 — Ayar dosyasını hazırlayın**

`.env.example` dosyasını `.env` olarak kopyalayın:

```bash
cp .env.example .env
```

`.env` içinde değiştirebileceğiniz temel ayarlar:

| Değişken | Varsayılan | Ne işe yarar |
|---|---|---|
| `ED_BT_ADE_DRY_RUN` | `true` | `true` iken hiçbir şey engellenmez. **Önce bu şekilde deneyin.** |
| `BASTIONFW_DASHBOARD_PORT` | `8080` | Panelin host üzerindeki portu. |
| `BASTIONFW_METRICS_PORT` | `9109` | Metriklerin host üzerindeki portu. |
| `BASTIONFW_LOG_ROOT` | `/var/log` | Hangi dizindeki loglar okunacak. |
| `ED_BT_ADE_LOG_LEVEL` | `INFO` | `DEBUG` daha ayrıntılı log verir. |

**Adım 3 — Dashboard erişim token'ı üretin (ÖNEMLİ)**

Panel, ağa açıldığında **kimse erişebilmesin** diye token ister. Üretin:

```bash
openssl rand -hex 32
```

Çıkan 64 karakterlik değeri `.env` dosyasına ekleyin:

```bash
ED_BT_ADE_DASHBOARD_TOKEN=<buraya-yapıştırın>
```

> **Bu adım atlanırsa panel açılmaz.** Token olmadan BastionFW, paneli güvenlik
> gereği yalnızca container'ın kendi `127.0.0.1` adresine bağlar; host'tan
> `http://localhost:8080` çalışmaz. Bu kasıtlı bir güvenlik davranışıdır —
> kimlik doğrulamasız bir panel internete açılırsa herkes sunucunuzun güvenlik
> durumunu görebilir.

**Adım 4 — Log dizinini hazırlayın**

```bash
sudo mkdir -p /var/log
```

`BASTIONFW_LOG_ROOT` içinde `auth.log` ve `nginx/access.log` yoksa motor çalışır
ama tespit yapamaz. Test için örnek log üretebilirsiniz:

```bash
sudo touch /var/log/auth.log
sudo mkdir -p /var/log/nginx && sudo touch /var/log/nginx/access.log
```

**Adım 5 — Başlatın**

```bash
docker compose up -d --build
```

İlk çalıştırma birkaç dakika sürebilir (WAF imajı kaynaktan derlenir).

**Adım 6 — Çalıştığını doğrulayın**

```bash
# Sağlık kontrolü (token gerektirmez)
curl http://127.0.0.1:9109/healthz
# Beklenen: ok

# Panele gidin (tarayıcıda token'ı girin)
# http://127.0.0.1:8080
```

**Adım 7 — Durdurun**

```bash
docker compose down          # durdur + kaldır
docker compose stop          # sadece durdur
docker compose logs -f bastionfw   # logları canlı izle
```

### 5.3 Panelde neler göreceksiniz?

Tarayıcıda `http://127.0.0.1:8080` adresini açıp token'ı girdikten sonra:

- **Mod rozeti** — `DRY-RUN` (sarı) veya `ACTIVE` (yeşil). Şu an güvenlik duvarına
  müdahale edip etmediğinizi bu gösterir.
- **İşlenen log sayısı** — motorun kaç satır okuduğu.
- **Tespit edilen tehdit sayısı** — kaç saldırı sinyali yakalandı.
- **Engellenen IP sayısı** — aktif ban sayısı (dry-run'da bu hep 0'dır).
- **Son alarmlar** — hangi kural, hangi IP, ne zaman.
- **Uptime ve kuyruk derinliği** — motorun sağlığı.

---

## 6. Kurulum — Yöntem B: Docker'sız, elle (host'a kurulum)

Bu yöntem **root olmayan** kullanıcılar ve sistem servisi olarak kurulum içindir.

### 6.1 Gereksinimler

- Python **3.11** veya üstü (`python3 --version`)
- `python3-venv` (paket yöneticinize göre: `apt install python3-venv`)
- Log dosyalarını **okuma** izni

### 6.2 Kurulum

```bash
git clone https://github.com/caganutkusaymaz1/BastionFW.git
cd BastionFW/bastionfw

python3 -m venv .venv
source .venv/bin/activate
pip install .
```

Artık komutlar `bastionfw` ya da `ed-bt-ade` adıyla çalışır:

```bash
bastionfw --help
```

### 6.3 Ayar dosyası

```bash
cp config.example.json config.myhost.json
```

`config.example.json` içindeki her alanı anlamıyla açıklayan bölüm için
bkz. [Yapılandırma rehberi](#8-yapılandırma-rehberi).

En az şunları kendi sisteminize göre değiştirin:

```jsonc
{
  "log_sources": [
    { "name": "auth", "path": "/var/log/auth.log" }   // gerçek SSH log yolunuz
  ]
}
```

### 6.4 Çalıştırma

**Motor (konsol/hizmet modu):**

```bash
python3 -m ed_bt_ade.sentinel --config config.myhost.json
```

**Panel (arayüz):**

```bash
python3 -m ed_bt_ade.dashboard --config config.myhost.json --port 8080
```

**Panel + motor (ikisi birlikte, önerilen):**

```bash
python3 -m ed_bt_ade.dashboard --config config.myhost.json --host 127.0.0.1 --port 8080
```

### 6.5 nftables hazırlığı (yalnızca gerçek engelleme kullanacaksanız)

BastionFW'in güvenlik duvarı sürücüsü, `inet ed_bt_ade` tablosunu **kendisi
yaratmaz** — sadece içine eleman ekler/çıkarır. Tabloyu bir kez siz oluşturursunuz:

```bash
sudo bash scripts/provision-nftables.sh     # idempotent: tekrar çalıştırmak güvenli
sudo nft list table inet ed_bt_ade          # doğrulama
```

Bu komut `blacklist` adlı bir IP seti, bir `input` zinciri ve
`ip saddr @blacklist drop` kuralı oluşturur.

### 6.6 Sistem servisi (systemd)

```bash
sudo cp deploy/ed-bt-ade.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ed-bt-ade
```

> ⚠️ **Uyarı:** Servis dosyası bir *başlangıç noktasıdır*. Dosya sistemi izinleri,
> capability'ler ve log yolları **sizin** altyapınıza göre gözden geçirilmelidir.

---

## 7. Yeni başlayanlar için: ilk 10 dakika

Elinizde hiçbir saldırı yokken sistemi denemek için sahte log üretin.

### Terminal 1 — motoru başlatın

```bash
cd BastionFW/bastionfw
bash run_dashboard.sh
```

Bu komut staging yapılandırmasıyla (tamamen dry-run) paneli başlatır ve
`staging-logs/auth.log` dosyasını izler.

### Terminal 2 — sahte saldırı üretin

```bash
cd BastionFW/bastionfw
bash demo-events.sh
```

### Terminal 3 — sonucu görün

Tarayıcıda `http://127.0.0.1:8080` → **Threats Detected** sayacı artar ve
şuna benzer bir alarm belirir:

```json
{
  "rule": "ssh_brute_force",
  "severity": "high",
  "ip": "203.0.113.10",
  "evidence": "3 failed attempts/60s"
}
```

Ya da JSON olarak:

```bash
curl http://127.0.0.1:8080/api/status | python3 -m json.tool
```

**Bu noktada hiçbir IP engellenmedi.** `ips_blocked` değeri `0` kalır — bu doğru
davranıştır. Gerçek engellemeye geçmek için [Bölüm 10](#10-saldırıları-gerçekten-engellemek-dry-run--gerçek)
adımını, sırasıyla izleyin.

---

## 8. Yapılandırma rehberi

Tüm ayarlar tek bir JSON dosyasındadır. `bastionfw/config.example.json` şablon
görevi görür.

### 8.1 `log_sources` — hangi dosyalar okunacak

```json
"log_sources": [
  {
    "name": "auth",
    "path": "/var/log/auth.log",
    "encoding": "utf-8",
    "poll_interval": 0.25
  }
]
```

| Alan | Açıklama |
|---|---|
| `name` | Bu kaynağın etiketi; alarmlarda görünür. |
| `path` | Okunacak dosyanın **tam yolu**. |
| `encoding` | Dosya karakter kodlaması (genelde `utf-8`). |
| `poll_interval` | Saniyede kaç kez kontrol edileceği. `0.25` = 250 ms. Çok düşük değerler disk yükünü artırır. |

Birden fazla kaynak ekleyebilirsiniz; her biri ayrı izlenir.

### 8.2 `firewall` — engelleme davranışı

```json
"firewall": {
  "enabled": false,
  "backend": "dry-run",
  "state_db": "state/firewall.sqlite3",
  "ban_seconds": 86400,
  "whitelist": []
}
```

| Alan | Açıklama |
|---|---|
| `enabled` | `false` iken motor tespit yapar, kaydeder, **engellemez**. |
| `backend` | `dry-run` (güvenli), `nftables`, `iptables`, `ufw`, `firewalld`. |
| `state_db` | Ban kayıtlarının tutulduğu SQLite dosyası. |
| `ban_seconds` | Bir ban kaç saniye sonra kalkar. `86400` = 24 saat. |
| `whitelist` | **Asla** engellenmeyecek IP/ağ listesi. Kendi sunucunuzu buraya ekleyin! |

> ⚠️ **Kritik:** `whitelist` boş bırakılırsa kendi IP'nizi engelleyebilirsiniz ve
> sunucuya erişimi kaybedersiniz. Önce kendi IP'nizi (`curl ifconfig.me`) ekleyin.

### 8.3 `detection` — eşik değerler

```json
"detection": {
  "ssh_failures": 8,
  "ssh_window_seconds": 60,
  "web_score_threshold": 2,
  "session_ttl_seconds": 3600
}
```

| Alan | Anlamı | Düşük değerin sonucu |
|---|---|---|
| `ssh_failures` | Kaç hatalı denemede alarm üretilsin. | Çok düşükse **siz** yanlış parola girince alarm çıkar. |
| `ssh_window_seconds` | Bu sayım kaç saniyelik pencereye bakılacak. | Çok kısaysa gerçek saldırıyı kaçırırsınız. |
| `web_score_threshold` | Web saldırısı puanı bu eşiği geçerse alarm. | Düşükse yanlış pozitif artar. |
| `session_ttl_seconds` | Bir tespit "aktif" sayılma süresi. | — |

### 8.4 `threat_intel` — dış tehdit istihbaratı (isteğe bağlı)

```json
"threat_intel": {
  "enabled": false,
  "cache_db": "state/threat-intel.sqlite3",
  "cache_ttl_seconds": 3600,
  "requests_per_second": 2,
  "circuit_failure_threshold": 5,
  "circuit_reset_seconds": 60,
  "abuseipdb_url": ""
}
```

Varsayılan olarak **kapalıdır**. Açarsanız motor, tespit edilen IP'lerin
itibar skorunu bir dış servise sorar. API anahtarını **JSON dosyasına yazmayın** —
ortam değişkeni olarak verin (`ED_BT_ADE_ABUSEIPDB_KEY`). Dış servis çökerse devre
kesici (circuit breaker) devreye girer ve motor **engelleme yapmadan** çalışmaya
devam eder.

### 8.5 `alerting` — webhook bildirimleri

```json
"alerting": {
  "webhooks": { "high": [], "critical": [] },
  "batch_size": 20,
  "flush_interval_seconds": 1,
  "requests_per_second": 5
}
```

`high` ve `critical` listelerine webhook adresleri eklerseniz, o seviyedeki
alarmlar oraya POST edilir.

> ⚠️ **Güvenlik notu:** Webhook adresleri yapılandırma yüklenirken güvenlik
> kontrolünden geçer. `localhost`, `127.0.0.1`, `169.254.169.254` gibi iç adresler
> **reddedilir** (SSRF koruması) — çünkü saldırgan kontrolünde bir webhook adresi
> verilirse motor istemeden sunucunuzun iç servislerine erişebilirdi.
> Gerçekten kullanmanız gereken iç servise erişmeniz gerekiyorsa
> `waf.trusted_internal_hosts` listesine ekleyin.

### 8.6 Ortam değişkenleri (JSON'u değiştirmeden ayar yapmak)

| Değişken | İşlevi |
|---|---|
| `ED_BT_ADE_DRY_RUN` | `true` ise JSON'daki ayarları **ezerek** her şeyi kuru çalıştırmaya alır. |
| `ED_BT_ADE_LOG_LEVEL` | Log seviyesi. |
| `ED_BT_ADE_DASHBOARD_TOKEN` | Panel erişim token'ı. |
| `ED_BT_ADE_ROLLBACK_SECONDS` | Deadman switch penceresi (saniye). |

### 8.7 Yapılandırma dosyasını doğrulama

```bash
python3 -c "from ed_bt_ade.config import load_config; load_config('config.myhost.json'); print('geçerli')"
```

Geçersizse nedenini açık bir hata mesajıyla söyler.

---

## 9. Panel ve API uçları

### 9.1 Panel

`http://127.0.0.1:8080` → "BastionFW Control Center". Token gerektiren yollar:
`/`, `/index.html`, `/api/status`, `/api/metrics`.

### 9.2 API

| Uç | Ne yapar | Yetki |
|---|---|---|
| `GET /` | Panel HTML'ini döndürür | Token gerekir |
| `GET /api/status` | Anlık durum JSON'u (tüm panel verisi buradan gelir) | Token gerekir |
| `GET /api/metrics` | Prometheus metrik metni | Token gerekir |
| `POST /api/login` | Token ile oturum çerezi alır | — |
| `GET /healthz` | `ok` döner | **Açık** (container sağlık kontrolü için) |
| `GET /metrics` | Prometheus metrikleri (metrik portu) | **Açık** |

`/healthz` ve `/metrics` **panel portunda değil**, `metrics_port` üzerindedir
(varsayılan `9109`). Bu ayrım kasıtlıdır: izleme sistemi token göndermeden
çalışabilsin diye.

### 9.3 Panel girişi

Token'ı `POST /api/login` ile gönderirseniz `HttpOnly`, `SameSite=Strict` bir
çerez alırsınız — böylece token tarayıcı JavaScript'ine hiç sızmaz.

Kaba kuvvet koruması: **5 hatalı deneme / 5 dakika → 60 saniye kilit** (`429`).
Her deneme audit loglanır, token'ın kendisi asla loglanmaz.

---

## 10. Saldırıları gerçekten engellemek (dry-run → gerçek)

Bu bölüm **sırayla izlenmelidir**. Her adımda ne olduğunu doğrulayın.

### Aşama 0 — Anlaşın: güvenlik duvarına dokunmak geri alınabilir olmalıdır

BastionFW "deadman switch" (ölüm düğmesi) mekanizması içerir: motor çökerse veya
donarsa, **root yetkisine sahip ayrı bir gözcü süreç** tüm banları kaldırır.
Böylece kendinizi dışarıda bırakmazsınız.

Bu gözcüyü **mutlaka** etkinleştirin (bkz. `docs/OPERATIONS.md`).

### Aşama 1 — Dry-run'da doğrulayın (varsayılan)

```json
"firewall": { "enabled": false, "backend": "dry-run", "whitelist": ["<KENDİ_IP'NİZ>"] }
```

En az birkaç gün çalıştırın. Panelde doğru IP'lerin tespit edildiğini ve
**yanlış alarm olmadığını** görün.

### Aşama 2 — Beyaz listeyi doldurun

```json
"whitelist": ["203.0.113.7", "198.51.100.0/24", "192.0.2.0/24"]
```

Kendi ofisinizin IP'si, VPN aralığınız, yedekleme sunucunuz, iSCSI/NAS adresleri…
**Bu adımı atlarsanız kendinizi kilitlersiniz.**

### Aşama 3 — nftables nesnelerini hazırlayın

```bash
sudo bash bastionfw/scripts/provision-nftables.sh
sudo nft list table inet ed_bt_ade
```

### Aşama 4 — Önce kısa süreli banlarla deneyin

```json
"firewall": {
  "enabled": true,
  "backend": "nftables",
  "ban_seconds": 300,
  "whitelist": ["<KENDİ_IP'NİZ>"]
}
```

5 dakikalık banlarla kısa bir süre test edin. Her şey yolundaysa süreyi artırın.

### Aşama 5 — Üretim değerlerine geçin

```json
"ban_seconds": 86400
```

### En tehlikeli an: "ya kendimi kilitlersem?"

Panik düğmesi — **tüm banları kaldırıp çıkış**:

```bash
python3 -m ed_bt_ade.sentinel --config config.json --purge-all-bans
```

### Sıfırdan kurulumda IPv6

Varsayılan olarak IPv6 banları **reddedilir ve loglanır** (IPv4'e özel bir sürücü
kullanıldığı için). Ayrıntı: `docs/OPERATIONS.md` §8.

---

## 11. WAF (Coraza + OWASP CRS)

WAF, sitenizin **önünde** duran ve kötü niyetli web isteklerini (SQL injection,
XSS, LFI...) uygulamanıza ulaşmadan eleyen katmandır.

### Kapatmak / açmak

`.env` dosyasında:

```bash
WAF_MODE=detect     # varsayılan: sadece logla, engelleme
WAF_MODE=block      # engellemeyi başlat
UPSTREAM_URL=http://app:3000   # korumanız altındaki uygulama
```

**`detect` → `block` geçişi hiçbir koşulda otomatik olmaz.** Bu bilinçli bir
operatör kararıdır; CRS kurallarının yanlış pozitifleri gerçek kullanıcıları
kilitleyebilir. Prosedür `docs/OPERATIONS.md` §"Promoting the WAF" bölümündedir.

### Doğrulama

```bash
bash deploy/waf/verify-block-mode.sh
```

Bu betik geçici bir upstream kurar, SQLi denemesiyle `block → 403` ve
`detect → 200` olduğunu kanıtlar, sonra her şeyi temizler.

---

## 12. Sık kullanılan komutlar

### Ban listesi içe / dışa aktarma

```bash
# Dışa aktar
python3 -m ed_bt_ade.lists export --format csv  --output bans.csv
python3 -m ed_bt_ade.lists export --format json --output bans.json

# İçe aktar (güvenlik denetiminden geçer)
python3 -m ed_bt_ade.lists import --format csv  --input bans.csv
python3 -m ed_bt_ade.lists import --format json --input bans.json --duration 3600
```

İçe aktarma, canlı hat ile **aynı** güvenlik kontrolünden geçer: yalnızca herkese
açık, beyaz listede olmayan IPv4 adresleri kabul edilir; diğerleri atlanır ve
loglanır.

### Motoru durdur / temizle

```bash
# Tüm banları kaldır (panik düğmesi)
python3 -m ed_bt_ade.sentinel --config config.json --purge-all-bans

# Yetki düşürmeyi atla (sadece geliştirme makinelerinde!)
python3 -m ed_bt_ade.sentinel --config config.json --no-privilege-drop
```

### Loglar

```bash
tail -f state/bastionfw.log            # motorun kendi logu (JSON satırları)
docker compose logs -f bastionfw       # container logları
```

---

## 13. Sorun giderme

### "Panel açılmıyor" / `http://localhost:8080` bağlantıyı reddediyor

**Neden:** `ED_BT_ADE_DASHBOARD_TOKEN` ayarlanmamış. Token olmadan motor, paneli
bilinçli olarak yalnızca `127.0.0.1`'e bağlar.

Loglarda bunu açıkça yazan bir uyarı görürsünüz:

```
ED_BT_ADE_DASHBOARD_TOKEN is not set; refusing to expose an
unauthenticated dashboard. Binding to 127.0.0.1 instead of 0.0.0.0.
```

**Çözüm:** `.env` dosyasına `openssl rand -hex 32` ile ürettiğiniz token'ı ekleyip
`docker compose up -d` çalıştırın.

### "Panel açılıyor ama `500 dashboard asset unavailable` hatası veriyor"

**Neden:** Container imajında `web/dashboard.html` yok (eski imaj).

**Çözüm:** `docker compose build --no-cache bastionfw && docker compose up -d`

> 3.2.2 ile bu hata düzeltildi: `Dockerfile` artık `bastionfw/web` dizinini
> kopyalıyor. 3.2.1 ve öncesi imajlarda panel arayüzü hiç yoktu.

### "`docker compose up` çok uzun sürüyor"

**Neden:** WAF imajı Caddy builder üzerinde kaynaktan derlenir (birkaç dakika).

**Çözüm:** Yalnızca motoru istiyorsanız WAF'e ihtiyacınız yoktur:

```bash
docker compose up -d bastionfw     # sadece motor, WAF derlenmez
```

### "Tespit edilen tehdit sayısı 0"

Kontrol edin:

1. `log_sources` içindeki yollar **gerçekten var mı**? (`ls` ile kontrol edin)
2. Log dosyası gerçekten yazılıyor mu?
3. Dosya izinleri: container `bastionfw` kullanıcısı (uid 10001) okuyabiliyor mu?
4. Eşikler çok yüksek mi? (`ssh_failures` = 8 iken 3 hata alarm üretmez)

### "Hiçbir şey engellenmiyor"

Bu **doğru davranış** olabilir:

- `ED_BT_ADE_DRY_RUN=true` ise hiçbir şey engellenmez (kasıtlı).
- `firewall.enabled` `false` ise engelleme yapılmaz.
- `backend` `dry-run` ise yalnızca kaydedilir.
- IP beyaz listedeyse engellenmez (bilinçli).
- IP özel ağ adresiyse her zaman reddedilir.

### "Kendimi dışladım"

```bash
# Envanterden bağımsız, kök yetkiyle:
sudo nft delete table inet ed_bt_ade

# Veya motorun kendi panik düğmesi:
python3 -m ed_bt_ade.sentinel --config config.json --purge-all-bans
```

### "Docker hata veriyor: `permission denied`"

Docker grubuna dahil olmanız gerekir:

```bash
sudo usermod -aG docker "$USER"    # sonra yeniden giriş yapın
```

---

## 14. Geliştirici bilgisi

### Python testleri

```bash
cd bastionfw
python3 -m unittest discover -s tests -v      # standart kütüphane
python3 -m pytest -q --cov=ed_bt_ade --cov-fail-under=80
```

Kapsam eşiği CI'da **%80**'dir ve düşürülemez.

### TypeScript çalışma alanı

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm run build
```

### CI'da otomatik çalışan kontroller

| Kontrol | Kapsam |
|---|---|
| `bandit -r ed_bt_ade -ll -q` | Python statik güvenlik analizi |
| `pytest --cov-fail-under=80` | Tam test paketi + %80 kapsam eşiği |
| `gitleaks` | Tüm geçmişte sır sızıntısı taraması |
| `pnpm audit --audit-level=high --prod` | NPM bağımlılık açıkları |
| Trivy `HIGH,CRITICAL` (exit 1) | Her iki container imajı |
| Syft CycloneDX SBOM | Her iki imaj için SBOM üretimi |
| `pip install --require-hashes` | Her Python paketi sha256 ile doğrulanır |
| Digest sabitli temel imaj | `python:3.13-slim@sha256:7c61…` — etiket değişimi imkânsız |
| SHA sabitli GitHub Actions | Her `uses:` 40 karakterlik commit SHA'sına sabitli — tag kaçırma mümkün değil |
| Semgrep `p/python` + `p/ci` | Statik analiz; `nosemgrep` yorumları gerekçelidir |

Tümü bloklayıcıdır (`continue-on-error: false`).

### Uzantı noktaları

| Uygulanacak arayüz | Ne için |
|---|---|
| `DetectionRule` | Yeni tespit kuralı |
| `FirewallDriver` | Siteye özel, set tabanlı firewall entegrasyonu |
| Threat-intel sağlayıcı adaptörü | Farklı bir istihbarat servisi |

Dış çağrıları **veri toplama döngüsünden uzak tutun** ve sağlayıcı hatasında
`None`/degraded davranışını koruyun — aksi halde dış servis kesintisi sizi
körleştirir.

---

## 15. Depo yapısı

```
BastionFW/
├── bastionfw/              ← Python motoru (asıl güvenlik bileşeni)
│   ├── ed_bt_ade/          ← kaynak kodu
│   │   ├── sentinel.py       motor döngüsü / CLI
│   │   ├── tailer.py         log okuma
│   │   ├── parsing.py        satır ayrıştırma
│   │   ├── detector.py       tespit kuralları
│   │   ├── firewall.py       güvenlik duvarı sürücüleri
│   │   ├── dashboard.py      web paneli
│   │   ├── config.py         yapılandırma + SSRF koruması
│   │   ├── lists.py          ban listesi içe/dışa aktarma
│   │   ├── waf_reputation.py WAF ↔ motor ban köprüsü
│   │   └── rollback.py       deadman switch
│   ├── tests/              ← 142 test
│   ├── web/dashboard.html  ← panel arayüzü
│   ├── deploy/             ← systemd birimleri, Grafana dashboard
│   └── scripts/            ← nftables hazırlık betiği
├── deploy/waf/             ← Coraza WAF (Caddyfile, Dockerfile, doğrulama)
├── docs/                   ← operasyon rehberi + önizleme sayfası
├── artifacts/
│   ├── api-server/           kimlik doğrulamalı Express API
│   ├── bastionfw-console/    React/Vite operasyon konsolu
│   └── mockup-sandbox/       yalnızca geliştirme amaçlı UI deneme alanı
├── lib/                    ← OpenAPI şeması, üretilmiş istemciler, veritabanı
├── Dockerfile              ← motor imajı
├── docker-compose.yml      ← motor + WAF yığını
├── THREAT_MODEL.md         ← tehdit modeli ve **dürüst bilinen sınırlar**
├── SECURITY.md             ← zafiyet bildirme süreci
└── CHANGELOG.md            ← sürüm geçmişi
```

---

## 16. Güvenlik duruşu

### Doğrulanmış güvenlik değişmezleri

- **Komut yürütme:** depoda **tek** bir subprocess çağrısı noktası vardır
  (`asyncio.create_subprocess_exec`, argv listesi, `shell=True` yok, `eval`/`exec` yok).
- **Ban evreni:** sisteme yazılan her adres geçerli/gerçek/`is_global`/beyaz listede
  değil kontrolünden geçer. Özel IP'ler asla engellenmez.
- **SSRF koruması:** yapılandırmadaki webhook ve tehdit istihbaratı adresleri,
  hostname'leri de çözümleyip (DNS) her çözülen IP'yi kontrol eder; iç ağ
  adreslerine (`169.254.169.254` dahil) istek atılması engellenir.
- **Geri dönüş penceresi:** motor sağlıklıyken liveness dosyası tazelenir; dış
  gözcü durursa tüm banları kaldırır.
- **WAF fail-open:** WAF uzun süre sağlıksız kalırsa dinamik deny-list temizlenir,
  arkadaki uygulama erişilebilir kalır.

### Bilinçli olarak yapılmayanlar

- **Bağımsız üçüncü taraf güvenlik denetimi yapılmamıştır.** Buradaki kontrollerin
  tamamı otomatiktir ve riski azaltır, ortadan kaldırmaz.
- Giriş hız sınırlayıcısı **bellek içidir**; yeniden başlatmada sıfırlanır.
- Konsol proxy'si ban/engelleme uygulamaz; uygulama motorun bulunduğu sunucuda
  yapılır.
- IPv6 banları varsayılan olarak devre dışıdır.

Bu maddelerin tam listesi için `THREAT_MODEL.md` → "Known limitations".

### Desteklenen sürümler

| Sürüm | Durum |
|---|---|
| 3.2.x | ✅ Destekleniyor |
| < 3.2 | ❌ Desteklenmiyor |

### Zafiyet bildirme

**Güvenlik açıkları için lütfen public issue açmayın.** GitHub Security
Advisories üzerinden özel olarak bildirin. Ayrıntı: `SECURITY.md`.

---

## Daha fazla okuma

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — tehdit modeli, güven sınırları, bilinen sınırlar
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — günlük operasyon, WAF geçişi, deadman tatbikatı
- [`SECURITY.md`](SECURITY.md) — zafiyet bildirme süreci
- [`CHANGELOG.md`](CHANGELOG.md) — sürüm geçmişi
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — katkı rehberi
- [`bastionfw/README.md`](bastionfw/README.md) — Python paketine özel detaylar
- [`bastionfw/KULLANIM-KILAVUZU.md`](bastionfw/KULLANIM-KILAVUZU.md) — kısa kullanım kılavuzu
- [`bastionfw/TEST-REPORT.md`](bastionfw/TEST-REPORT.md) — test raporu

## Lisans

MIT — bkz. [`bastionfw/LICENSE`](bastionfw/LICENSE).
