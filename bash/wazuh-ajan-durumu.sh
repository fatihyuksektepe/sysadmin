#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fatih Yüksektepe
#                      fatih@yuksektepe.org
#
# wazuh-ajan-durumu.sh
#
# Wazuh sunucusunun API'sinden bütün ajanları çeker ve sorunlu olanları listeler.
# SALT OKUNUR: API'de hiçbir şeyi değiştirmez, ajan silmez, yeniden başlatmaz.
#
# Kontroller:
#   W01  Bağlantısı kopmuş ajanlar (disconnected)
#   W02  Uzun süredir bağlanmayan ajanlar (--gun günden eski keepalive, silme adayı)
#   W03  Hiç bağlanmamış ajanlar (never_connected)
#   W04  Kaydı yarım kalmış ajanlar (pending)
#   W05  Sürümü yöneticiden eski ajanlar
#   W06  Hiçbir gruba atanmamış ajanlar
#   W07  Grup yapılandırması senkron olmayan ajanlar
#   W08  Aynı IP'yi kullanan birden fazla ajan (klonlanmış VM'lerde sık görülür)
#
# Gerekenler: bash 4+, curl, jq. Linux ve macOS'ta çalışır.
#
# Kullanım:
#   ./wazuh-ajan-durumu.sh -s https://wazuh.ornek.local:55000 -u wazuh
#   WAZUH_SIFRE='...' ./wazuh-ajan-durumu.sh -s https://10.0.0.5:55000 -k -g 30
#
# Parametreler:
#   -s, --sunucu URL      API adresi (varsayılan: https://localhost:55000)
#   -u, --kullanici AD    API kullanıcısı (varsayılan: $WAZUH_KULLANICI ya da wazuh)
#   -g, --gun N           W02 için eşik, gün (varsayılan: 7)
#   -o, --cikti KLASOR    CSV'lerin yazılacağı klasör (varsayılan: ./wazuh-rapor-TARIH)
#       --ayirici K       CSV ayırıcısı (varsayılan: ;  Türkçe Excel bunu doğru açar)
#       --ca DOSYA        API sertifikasını doğrulamak için CA dosyası
#   -k, --guvensiz        Sertifikayı doğrulama (Wazuh'un varsayılan self-signed sertifikası için)
#   -h, --help            Bu yardımı göster
#
# Şifre $WAZUH_SIFRE ortam değişkeninden okunur, yoksa sorulur. Şifre ve token
# curl'e komut satırından değil stdin'den verilir, ps çıktısında görünmez.
# API kullanıcısının en az agent:read ve manager:read yetkisi olması yeterli.
#
# Çıkış kodları:
#   0  Bulgu yok
#   1  Hata (bağlantı, kimlik doğrulama, eksik araç...)
#   2  En az bir bulgu var
# Böylece cron'dan ya da izleme sisteminden çağırıp sonuca göre uyarı üretebilirsin.
#
# Sürüm: 0.1.0

set -euo pipefail

SUNUCU="https://localhost:55000"
KULLANICI="${WAZUH_KULLANICI:-wazuh}"
GUN=7
CIKTI=""
AYIRICI=";"
CA_DOSYASI=""
GUVENSIZ=0
SAYFA=500

yardim() {
  # Dosyanın başındaki açıklama bloğunu yardım olarak bas
  sed -n '5,/^$/{s/^# \{0,1\}//;p;}' "$0"
}

hata() {
  echo "HATA: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--sunucu)    SUNUCU="${2:?--sunucu değer bekliyor}"; shift 2 ;;
    -u|--kullanici) KULLANICI="${2:?--kullanici değer bekliyor}"; shift 2 ;;
    -g|--gun)       GUN="${2:?--gun değer bekliyor}"; shift 2 ;;
    -o|--cikti)     CIKTI="${2:?--cikti değer bekliyor}"; shift 2 ;;
    --ayirici)      AYIRICI="${2:?--ayirici değer bekliyor}"; shift 2 ;;
    --ca)           CA_DOSYASI="${2:?--ca değer bekliyor}"; shift 2 ;;
    -k|--guvensiz)  GUVENSIZ=1; shift ;;
    -h|--help)      yardim; exit 0 ;;
    *)              hata "Bilinmeyen parametre: $1 (yardım için -h)" ;;
  esac
done

for arac in curl jq; do
  command -v "$arac" >/dev/null 2>&1 || hata "$arac bulunamadı, önce kurman gerekiyor."
done
[[ "$GUN" =~ ^[0-9]+$ ]] || hata "--gun pozitif bir tam sayı olmalı: $GUN"
[[ ${#AYIRICI} -eq 1 ]] || hata "--ayirici tek karakter olmalı: $AYIRICI"
[[ -z "$CA_DOSYASI" || -r "$CA_DOSYASI" ]] || hata "CA dosyası okunamıyor: $CA_DOSYASI"
SUNUCU="${SUNUCU%/}"
CIKTI="${CIKTI:-./wazuh-rapor-$(date +%Y%m%d-%H%M)}"

SIFRE="${WAZUH_SIFRE:-}"
if [[ -z "$SIFRE" ]]; then
  [[ -t 0 ]] || hata "WAZUH_SIFRE tanımlı değil ve şifre sorulacak bir terminal yok."
  read -rsp "$KULLANICI için API şifresi: " SIFRE
  echo
fi

CURL_ORTAK=(--silent --show-error --fail --connect-timeout 10 --max-time 60)
if [[ $GUVENSIZ -eq 1 ]]; then
  CURL_ORTAK+=(--insecure)
elif [[ -n "$CA_DOSYASI" ]]; then
  CURL_ORTAK+=(--cacert "$CA_DOSYASI")
fi

# curl config dosyasında " ve \ kaçırılmalı
curl_kacir() {
  local s="${1//\\/\\\\}"
  printf '%s' "${s//\"/\\\"}"
}

# --- Kimlik doğrulama -------------------------------------------------------

curl_hata_ipucu() {
  case "$1" in
    60|35|51|58|77) echo "Sertifika doğrulanamadı. Kendi CA'n varsa --ca ile ver, self-signed ise -k kullan." ;;
    6|7|28)         echo "Sunucuya ulaşılamadı. Adresi, portu (55000) ve güvenlik duvarını kontrol et." ;;
    22)             echo "API hata döndü. Kullanıcı adı / şifre ya da yetkiler yanlış olabilir." ;;
    *)              echo "curl çıkış kodu: $1" ;;
  esac
}

kod=0
TOKEN=$(printf 'user = "%s:%s"\n' "$(curl_kacir "$KULLANICI")" "$(curl_kacir "$SIFRE")" \
  | curl "${CURL_ORTAK[@]}" -K - -X POST "$SUNUCU/security/user/authenticate?raw=true") || kod=$?
unset SIFRE
[[ $kod -eq 0 && -n "$TOKEN" ]] || hata "Kimlik doğrulama başarısız. $(curl_hata_ipucu "$kod")"

api_get() {
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" \
    | curl "${CURL_ORTAK[@]}" -K - "$SUNUCU$1"
}

# --- Veri toplama -----------------------------------------------------------

YONETICI_SURUMU=$(api_get "/manager/info" | jq -r '.data.affected_items[0].version // empty') \
  || hata "Yönetici bilgisi alınamadı."
[[ -n "$YONETICI_SURUMU" ]] || hata "Yönetici sürümü okunamadı, API yanıtı beklenenden farklı."

ALANLAR="id,name,ip,status,version,lastKeepAlive,dateAdd,os.name,os.version,group,group_config_status,node_name"
# Sayfaları geçici dosyalara yazıp sonra birleştiriyoruz. Binlerce ajanlık
# listeyi jq'ya argüman olarak vermek Linux'un argüman boyu sınırına takılıyor.
GECICI=$(mktemp -d)
trap 'rm -rf "$GECICI"' EXIT

offset=0
while :; do
  api_get "/agents?limit=$SAYFA&offset=$offset&select=$ALANLAR&sort=%2Bid" \
    > "$GECICI/sayfa-$(printf '%06d' "$offset").json" \
    || hata "Ajan listesi alınamadı (offset=$offset)."
  toplam=$(jq -r '.data.total_affected_items' "$GECICI/sayfa-$(printf '%06d' "$offset").json")
  offset=$((offset + SAYFA))
  [[ $offset -lt $toplam ]] || break
done

# 000 yöneticinin kendisi, onu saymıyoruz
jq -s 'map(.data.affected_items[]) | map(select(.id != "000"))' "$GECICI"/sayfa-*.json \
  > "$GECICI/ajanlar.json"

# --- Analiz -----------------------------------------------------------------
#
# Bütün hesaplar jq içinde yapılıyor; böylece GNU/BSD date farkına takılmıyoruz.
# Wazuh tarihleri UTC döndürür ("2026-01-05T08:12:44+00:00" ya da "...Z").

# shellcheck disable=SC2016  # jq değişkenleri, kabuk genişletmesin
ANALIZ='
  def epoch: if . == null or . == "" then null
             else (.[0:19] + "Z" | try fromdateiso8601 catch null) end;
  def surum: (. // "") | [scan("[0-9]+") | tonumber];
  def gun_once($t): if $t == null then null else ((now - $t) / 86400 | floor) end;

  ($yonetici | surum) as $ys
  | map(. + {
      os:     ([.os.name, .os.version] | map(select(. != null)) | join(" ")),
      grup:   ((.group // []) | join(",")),
      kopali: (.lastKeepAlive | epoch | gun_once(.))
    })
  | (map(select(.ip != null and .ip != "any" and .ip != ""))
     | group_by(.ip) | map(select(length > 1)) | map({(.[0].ip): map(.name)}) | add // {}) as $ciftip
  | [ .[] as $a
      | ( if $a.status == "disconnected" and ($a.kopali == null or $a.kopali < $esik) then
            ["W01","Orta", "Bağlantısı kopmuş", "Son keepalive: \($a.lastKeepAlive // "-") (\($a.kopali // "?") gün önce)"] else empty end,
          if $a.status == "disconnected" and $a.kopali != null and $a.kopali >= $esik then
            ["W02","Yüksek","Uzun süredir bağlanmıyor", "\($a.kopali) gündür yok, son keepalive: \($a.lastKeepAlive). Silme adayı."] else empty end,
          if $a.status == "never_connected" then
            ["W03","Orta", "Hiç bağlanmamış", "Eklenme tarihi: \($a.dateAdd // "-")"] else empty end,
          if $a.status == "pending" then
            ["W04","Düşük","Kaydı tamamlanmamış", "Eklenme tarihi: \($a.dateAdd // "-")"] else empty end,
          if ($a.version // "") != "" and ($a.version | surum) < $ys then
            ["W05","Düşük","Sürümü eski", "\($a.version), yönetici \($yonetici)"] else empty end,
          if $a.status != "never_connected" and $a.grup == "" then
            ["W06","Düşük","Gruba atanmamış", "Sadece varsayılan politika uygulanıyor olabilir"] else empty end,
          if $a.status == "active" and ($a.group_config_status // "synced") != "synced" then
            ["W07","Düşük","Grup yapılandırması senkron değil", "group_config_status: \($a.group_config_status)"] else empty end,
          if $ciftip[$a.ip // ""] != null then
            ["W08","Orta", "IP başka ajanla çakışıyor", "Aynı IP: \($ciftip[$a.ip] | join(", "))"] else empty end
        )
      | {kod: .[0], seviye: .[1], baslik: .[2], detay: .[3],
         id: $a.id, ad: $a.name, ip: ($a.ip // ""), durum: $a.status, surum: ($a.version // ""), os: $a.os}
    ] as $bulgular
  | {ajanlar: ., bulgular: ($bulgular | sort_by(.kod, .id))}
'

jq -c --arg yonetici "$YONETICI_SURUMU" --argjson esik "$GUN" "$ANALIZ" \
  "$GECICI/ajanlar.json" > "$GECICI/sonuc.json"
SONUC="$GECICI/sonuc.json"

# --- Çıktı ------------------------------------------------------------------

mkdir -p "$CIKTI"

jq -r --arg d "$AYIRICI" '
  def csv: map(tostring | gsub("\""; "\"\"") | "\"" + . + "\"") | join($d);
  (["ID","Ad","IP","Durum","Sürüm","İşletim sistemi","Grup","Son keepalive","Kaç gün önce","Eklenme","Düğüm"] | csv),
  (.ajanlar[] | [.id, .name, (.ip // ""), .status, (.version // ""), .os, .grup,
                 (.lastKeepAlive // ""), (.kopali // ""), (.dateAdd // ""), (.node_name // "")] | csv)
' "$SONUC" > "$CIKTI/ajanlar.csv"

jq -r --arg d "$AYIRICI" '
  def csv: map(tostring | gsub("\""; "\"\"") | "\"" + . + "\"") | join($d);
  (["Kod","Seviye","Bulgu","ID","Ad","IP","Durum","Sürüm","İşletim sistemi","Detay"] | csv),
  (.bulgular[] | [.kod, .seviye, .baslik, .id, .ad, .ip, .durum, .surum, .os, .detay] | csv)
' "$SONUC" > "$CIKTI/bulgular.csv"

{
  echo "Wazuh ajan durum raporu"
  echo "Tarih     : $(date '+%Y-%m-%d %H:%M')"
  echo "Sunucu    : $SUNUCU"
  echo "Yönetici  : $YONETICI_SURUMU"
  echo "W02 eşiği : $GUN gün"
  echo
  jq -r '
    .ajanlar | length as $n
    | "Toplam ajan: \($n)",
      (group_by(.status)[] | "  \(.[0].status): \(length)")
  ' "$SONUC"
  echo
  jq -r '
    if (.bulgular | length) == 0 then "Bulgu yok."
    else
      "Bulgular:",
      (.bulgular | group_by(.kod)[] | "  \(.[0].kod)  \(.[0].baslik) [\(.[0].seviye)]: \(length) ajan"),
      "",
      "Ayrıntılar:",
      (.bulgular[] | "  \(.kod)  \(.id)  \(.ad)  \(.ip)  \(.detay)")
    end
  ' "$SONUC"
  echo
  echo "Dosyalar: $CIKTI/ajanlar.csv, $CIKTI/bulgular.csv"
} | tee "$CIKTI/ozet.txt"

[[ $(jq '.bulgular | length' "$SONUC") -eq 0 ]] || exit 2
