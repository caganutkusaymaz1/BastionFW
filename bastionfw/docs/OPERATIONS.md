# BastionFW Operasyon Rehberi

**Geliştirici:** Çağan Utku Saymaz

## 1. Kurulum

Python 3.11 veya daha yeni bir Linux host gerekir. Paket bağımlılığı yoktur.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m unittest discover -s tests -v
```

Servis hesabının okuyacağı log dosyalarına erişimi olmalıdır. State dizini
yalnızca servis hesabı tarafından yazılabilir olmalıdır.

## 2. İlk çalıştırma: staging/dry-run

```bash
mkdir -p staging-logs state
: > staging-logs/auth.log
python -m ed_bt_ade.sentinel --config config.staging.json
```

Başka bir terminalde test olayları üretilebilir:

```bash
for n in 1 2 3; do
  echo "Failed password for root from 203.0.113.10" >> staging-logs/auth.log
done
curl -fsS http://127.0.0.1:19109/healthz
curl -fsS http://127.0.0.1:19109/metrics
```

`203.0.113.0/24` dokümantasyon için ayrılmış bir ağdır; gerçek saldırı
trafiğini taklit etmek yerine staging testlerinde kullanılmalıdır.

## 3. Gerçek firewall etkinleştirme sırası

1. Önce en az 24 saat dry-run metriklerini ve tespit oranlarını gözlemleyin.
2. Yönetim IP'lerini ve yönetim CIDR'larını whitelist'e ekleyin.
3. `backend` değerini hostta gerçekten kullanılan sürücüye sabitleyin.
4. Firewall'ın mevcut ruleset/set yapısını manuel olarak doğrulayın.
5. Kısa `ban_seconds` değeriyle sınırlı staging denemesi yapın.
6. Ancak bundan sonra `firewall.enabled=true` yapın.

Loopback, RFC1918, link-local ve whitelist adresleri kod seviyesinde reddedilir.
Buna rağmen whitelist, ağ erişim politikasının yerine geçmez; host firewall
kuralları ve out-of-band erişim ayrıca doğrulanmalıdır.

## 4. Threat intelligence ve webhooklar

Threat intelligence varsayılan olarak kapalıdır. Sağlayıcı URL'si
`threat_intel.abuseipdb_url` üzerinden yapılandırılır. API anahtarlarını
konfigürasyon dosyasına yazmayın. AbuseIPDB için anahtar
`ED_BT_ADE_ABUSEIPDB_KEY` environment/secret değişkeninden okunur; üretimde
secret yönetimi kullanın.

Webhook URL'leri `alerting.webhooks` altında severity seviyesine göre gruplanır.
Dispatcher batch gönderir, rate limit uygular ve dış servis hatalarını ana
ingestion pipeline'ına taşımaz.

## 5. systemd

`deploy/ed-bt-ade.service` örneğini host yollarına göre düzenleyin. Servis
hesabı, log okuma izinleri, state dizini ve gerekli firewall yetkileri tek tek
incelenmelidir. `NoNewPrivileges` ile `CAP_NET_ADMIN` birlikte kullanıldığı
için dağıtım politikanıza göre bunlardan biri değiştirilebilir.

## 6. İzleme ve geri dönüş

- `/healthz`: servis hazırsa HTTP 200 döner.
- `/metrics`: işlenen log, tespit, engelleme, hata ve son pipeline gecikmesini
  Prometheus metin formatında verir.
- JSON loglar stdout'a yazılır; journald veya merkezi log collector'a
  yönlendirilebilir.
- Yanlış pozitiflerde önce `firewall.enabled=false` ile enforcement'ı kapatın,
  sonra kural eşiklerini ve whitelist'i düzeltin.

## 7. Dağıtık mimari sınırı

Bu paket host-local agent'tır. Yüzlerce host için her hostta bir agent,
merkezi event bus, merkezi politika/config dağıtımı, mTLS kimlikleri,
merkezi deduplikasyon ve fleet-level audit katmanı gerekir. SQLite yalnızca
host-local ban ve reputation cache state'i içindir; merkezi koordinasyon
amacıyla kullanılmamalıdır.