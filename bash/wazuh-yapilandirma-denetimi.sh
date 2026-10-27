#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fatih Yüksektepe
#                      fatih@yuksektepe.org
#
# wazuh-yapilandirma-denetimi.sh
#
# Wazuh sunucusunun yapılandırmasını baştan sona denetler: manager (ossec.conf),
# API, indexer, Filebeat, dashboard, servisler ve sertifikalar. Tek sunuculu
# (all-in-one) kurulumda hepsini, dağıtık kurulumda o sunucuda ne varsa onu kontrol eder.
# SALT OKUNUR: hiçbir dosyayı değiştirmez, servis yeniden başlatmaz.
#
# Wazuh 4.8 ve sonrası için yazıldı. Manager üzerinde root ile çalıştırılır.
#
# Kontroller:
#   Manager
#     M01  ossec.conf geçerli XML mi
#     M02  Dosya bütünlüğü izleme (syscheck) açık mı
#     M03  syscheck tarama sıklığı
#     M04  Gerçek zamanlı / whodata ile izlenen dizin var mı
#     M05  SCA açık mı
#     M06  Syscollector ve paket envanteri açık mı (zafiyet tespiti buna bağlı)
#     M07  Zafiyet tespiti (vulnerability-detection) açık mı
#     M08  4.8'de kaldırılan vulnerability-detector bloğu kalmış mı
#     M09  <indexer> bağlantısı: https, CA / sertifika / anahtar dosyaları
#     M10  logall / logall_json (arşiv diski doldurur)
#     M11  Alarm eşiği (log_alert_level)
#     M12  Syslog alımında allowed-ips
#     M13  Ajan kaydı (authd) parola ya da sertifika istiyor mu
#     M14  Cluster ayarları (anahtar, düğüm adresleri)
#     M15  E-posta bildirimi açık ama SMTP sunucusu yok
#     M16  local_internal_options.conf içinde debug ayarı
#     M17  ossec.log'daki son ERROR / CRITICAL kayıtları
#     M18  analysisd'nin düşürdüğü olaylar
#   API
#     A01  HTTPS açık mı
#     A02  CORS her kaynağa açık mı
#     A03  İstek sınırı ve kaba kuvvet koruması
#     A04  Log seviyesi debug mı
#     A05  Varsayılan API parolaları (wazuh/wazuh, wazuh-wui/wazuh-wui)
#   Indexer
#     I01  Demo sertifikalara izin verilmiş mi
#     I02  HTTP katmanında TLS kapalı mı
#     I03  JVM heap boyutu
#     I04  vm.max_map_count
#     I05  Varsayılan parolalar (admin/admin, kibanaserver/kibanaserver)
#     I06  Cluster sağlığı ve atanmamış shard'lar        (*)
#     I07  Düğüm başına shard sayısı                     (*)
#     I08  Disk doluluğu ve watermark eşikleri            (*)
#     I09  Salt okunur kalmış indeksler                   (*)
#     I10  wazuh-alerts için ISM saklama politikası       (*)
#     I11  wazuh indeks şablonu yüklü mü                  (*)
#     I12  wazuh-alerts indeks sayısı ve toplam boyutu    (*)
#   Filebeat
#     F01  Indexer'a https ile bağlanıyor mu
#     F02  Sertifika doğrulaması kapalı mı
#     F03  alerts / archives modülleri
#     F04  filebeat test output
#   Dashboard
#     D01  HTTPS kapalı mı
#     D02  Indexer sertifikası doğrulanıyor mu
#     D03  wazuh.yml içinde varsayılan API parolası
#   Sistem
#     S01  Servisler çalışıyor ve açılışta başlıyor mu
#     S02  Bileşen sürümleri aynı mı
#     S03  Disk doluluğu (/var/ossec ve indexer veri dizini)
#     S04  Saat senkronizasyonu (NTP)
#     S05  Anahtar ve gizli bilgi içeren dosyaların izinleri
#     S06  Dinlenen Wazuh portları
#   Sertifikalar
#     C01  Süresi dolmuş ya da dolmak üzere olan sertifikalar
#     C02  Zayıf RSA anahtarı ya da SHA-1 imza
#     C03  OpenSearch demo sertifikaları
#
#   (*) Indexer API'sine bağlanır. Şifre $WAZUH_INDEXER_SIFRE ortam değişkeninden
#       okunur, yoksa sorulur. Boş geçilirse bu kontroller atlanır.
#
# Gerekenler: bash 4+, curl, openssl. XML, YAML ve JSON dosyalarını Wazuh'un kendi
# Python'u (/var/ossec/framework/python) ile okur, ayrıca bir şey kurmak gerekmez.
#
# Kullanım:
#   sudo ./wazuh-yapilandirma-denetimi.sh
#   sudo WAZUH_INDEXER_SIFRE='...' ./wazuh-yapilandirma-denetimi.sh -o /root/denetim
#   sudo ./wazuh-yapilandirma-denetimi.sh -i https://10.0.0.20:9200 -U admin
#
# Parametreler:
#   -U, --indexer-kullanici AD  Indexer API kullanıcısı (varsayılan: admin)
#   -i, --indexer URL           Indexer adresi (varsayılan: opensearch.yml'den, o yoksa
#                               ossec.conf'taki <indexer> bloğundan)
#   -o, --cikti KLASOR          Çıktı klasörü (varsayılan: ./wazuh-denetim-TARIH)
#       --ayirici K             CSV ayırıcısı (varsayılan: ;  Türkçe Excel bunu doğru açar)
#       --sertifika-gun N       Bu kadar gün içinde dolacak sertifikaları uyar (varsayılan: 30)
#       --parola-denemesi-yok   Varsayılan parola denemelerini (A05, I05) yapma
#   -h, --help                  Bu yardımı göster
#
# Varsayılan parola denemeleri sadece bu sunucunun kendi API'sine ve indexer'ına
# yapılır, kullanıcı başına bir istek. Başarısız deneme sayısı Wazuh'un kilitleme
# sınırının çok altında kalır.
#
# Çıkış kodları:
#   0  Bulgu yok (sadece Bilgi ve Tamam)
#   1  Hata (root değil, Wazuh bulunamadı, eksik araç...)
#   2  En az bir Kritik, Yüksek, Orta ya da Düşük bulgu var
#
# Sürüm: 0.1.0

# -e kullanmıyoruz: kontrollerin çoğu "bulunamadı" durumunda sıfırdan farklı döner,
# biri takıldı diye denetimin yarıda kalmasını istemiyoruz.
set -uo pipefail

OSSEC=/var/ossec
INDEXER_KULLANICI="${WAZUH_INDEXER_KULLANICI:-admin}"
INDEXER_URL=""
CIKTI=""
AYIRICI=";"
SERTIFIKA_GUN=30
PAROLA_DENE=1

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
    -U|--indexer-kullanici) INDEXER_KULLANICI="${2:?--indexer-kullanici değer bekliyor}"; shift 2 ;;
    -i|--indexer)           INDEXER_URL="${2:?--indexer değer bekliyor}"; shift 2 ;;
    -o|--cikti)             CIKTI="${2:?--cikti değer bekliyor}"; shift 2 ;;
    --ayirici)              AYIRICI="${2:?--ayirici değer bekliyor}"; shift 2 ;;
    --sertifika-gun)        SERTIFIKA_GUN="${2:?--sertifika-gun değer bekliyor}"; shift 2 ;;
    --parola-denemesi-yok)  PAROLA_DENE=0; shift ;;
    -h|--help)              yardim; exit 0 ;;
    *)                      hata "Bilinmeyen parametre: $1 (yardım için -h)" ;;
  esac
done

[[ $EUID -eq 0 ]] || hata "root olarak çalıştırılmalı (sudo)."
[[ -d $OSSEC ]] || hata "$OSSEC bulunamadı, bu sunucu bir Wazuh manager değil gibi."
for arac in curl openssl awk; do
  command -v "$arac" >/dev/null 2>&1 || hata "$arac bulunamadı, önce kurman gerekiyor."
done
[[ "$SERTIFIKA_GUN" =~ ^[0-9]+$ ]] || hata "--sertifika-gun pozitif bir tam sayı olmalı: $SERTIFIKA_GUN"
[[ ${#AYIRICI} -eq 1 ]] || hata "--ayirici tek karakter olmalı: $AYIRICI"

PY="$OSSEC/framework/python/bin/python3"
[[ -x $PY ]] || PY=$(command -v python3 || true)
[[ -n $PY ]] || hata "Python bulunamadı ($OSSEC/framework/python ya da python3)."

CIKTI="${CIKTI:-./wazuh-denetim-$(date +%Y%m%d-%H%M)}"
GECICI=$(mktemp -d)
trap 'rm -rf "$GECICI"' EXIT
BULGULAR="$GECICI/bulgular.tsv"
: > "$BULGULAR"

# --- Yardımcılar ------------------------------------------------------------
#
# Yapılandırma dosyaları "yol<TAB>değer<TAB>blok" satırlarına çevrilir, kontroller
# bu düz listeden awk ile okunur. XML'de yol "syscheck/disabled", name özniteliği
# olanlar "wodle[syscollector]/disabled", öznitelikler "syscheck/directories@realtime"
# biçiminde. YAML ve JSON'da yol noktalı: "output.elasticsearch.hosts.0".
# Blok, ossec.conf'ta kaçıncı üst seviye eleman olduğunu tutar; aynı adlı birden
# fazla <remote> gibi blokları ayırmak için.

cat > "$GECICI/duz.py" <<'PY'
import json, re, sys

def yaz(yol, deger, blok=""):
    if isinstance(deger, bool):
        deger = "true" if deger else "false"
    elif deger is None:
        deger = ""
    deger = re.sub(r"\s+", " ", str(deger)).strip()
    print(f"{yol}\t{deger}\t{blok}")

def gez(o, yol=""):
    if isinstance(o, dict):
        for k, v in o.items():
            gez(v, f"{yol}.{k}" if yol else str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            gez(v, f"{yol}.{i}" if yol else str(i))
    else:
        yaz(yol, o)

def xml_gez(e, yol, blok):
    ad = e.tag + (f"[{e.get('name')}]" if e.get("name") else "")
    yol = f"{yol}/{ad}" if yol else ad
    for k, v in e.attrib.items():
        yaz(f"{yol}@{k}", v, blok)
    cocuklar = list(e)
    if cocuklar:
        for c in cocuklar:
            xml_gez(c, yol, blok)
    else:
        yaz(yol, e.text or "", blok)

tur, dosya = sys.argv[1], sys.argv[2]
metin = open(dosya, encoding="utf-8", errors="replace").read()
if tur == "json":
    gez(json.loads(metin) if metin.strip() else {})
elif tur == "yaml":
    import yaml
    gez(yaml.safe_load(metin) or {})
else:
    import xml.etree.ElementTree as ET
    # ossec.conf birden fazla <ossec_config> içerebilir, tek kök altında topluyoruz
    metin = re.sub(r"<\?xml[^>]*\?>", "", metin)
    kok = ET.fromstring("<kok>" + metin + "</kok>")
    blok = 0
    for oc in kok:
        for e in oc:
            blok += 1
            xml_gez(e, "", blok)
PY

# tür dosya -> düz liste; hata olursa boş liste ve sıfırdan farklı çıkış
duzlestir() {
  "$PY" "$GECICI/duz.py" "$1" "$2" 2>"$GECICI/py-hata.txt"
}
# Anahtarın son değeri (ossec.conf'ta sonraki blok öncekini ezer)
al() { awk -F'\t' -v k="$2" '$1==k{d=$2} END{print d}' "$1"; }
# Anahtarın bütün değerleri
hepsi() { awk -F'\t' -v k="$2" '$1==k{print $2}' "$1"; }
# Yolu regex'e uyan bütün değerler. Regex -v ile değil ortamdan veriliyor;
# -v ters bölüleri yorumlar ve "\[" gibi kaçışları bozar.
eslesen() { R="$2" awk -F'\t' '$1~ENVIRON["R"]{print $2}' "$1"; }
# Anahtar ya da regex'e uyan bir yol var mı
var_mi() { awk -F'\t' -v k="$2" '$1==k{b=1} END{exit !b}' "$1"; }
yol_var_mi() { R="$2" awk -F'\t' '$1~ENVIRON["R"]{b=1} END{exit !b}' "$1"; }

evet()  { case "${1,,}" in yes|true|1|on) return 0 ;; esac; return 1; }
hayir() { case "${1,,}" in no|false|0|off) return 0 ;; esac; return 1; }

tek_satir() { local s="${1//$'\t'/ }"; printf '%s' "${s//$'\n'/ | }"; }

# kod seviye bileşen başlık [detay] [öneri]
bulgu() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(tek_satir "$4")" \
    "$(tek_satir "${5:-}")" "$(tek_satir "${6:-}")" >> "$BULGULAR"
}
tamam() { bulgu "$1" Tamam "$2" "$3" "${4:-}"; }
bilgi() { bulgu "$1" Bilgi "$2" "$3" "${4:-}" "${5:-}"; }

# curl config dosyasında " ve \ kaçırılmalı
curl_kacir() {
  local s="${1//\\/\\\\}"
  printf '%s' "${s//\"/\\\"}"
}

# Boyut (512m, 4g...) -> MB
mb() {
  local s="${1,,}" n
  n="${s//[!0-9]/}"
  [[ -n $n ]] || { echo 0; return; }
  case "$s" in
    *g) echo $((n * 1024)) ;;
    *m) echo "$n" ;;
    *k) echo $((n / 1024)) ;;
    *)  echo $((n / 1024 / 1024)) ;;
  esac
}

surum_kisa() { grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<<"$1" | head -n1; }

paket_surum() {
  local v
  if command -v dpkg-query >/dev/null 2>&1; then
    v=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$1" 2>/dev/null)
    [[ $v == installed\ * ]] && { surum_kisa "${v#installed }"; return; }
  fi
  if command -v rpm >/dev/null 2>&1; then
    v=$(rpm -q --qf '%{VERSION}' "$1" 2>/dev/null) && { surum_kisa "$v"; return; }
  fi
}

# --- Yapılandırmaları oku ---------------------------------------------------

CONF="$OSSEC/etc/ossec.conf"
OC="$GECICI/ossec.tsv"
API_YAML="$OSSEC/api/configuration/api.yaml"
AY="$GECICI/api.tsv"
IX_YML=/etc/wazuh-indexer/opensearch.yml
IY="$GECICI/indexer.tsv"
FB_YML=/etc/filebeat/filebeat.yml
FY="$GECICI/filebeat.tsv"
DB_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
DY="$GECICI/dashboard.tsv"
WZ_YML=/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
WY="$GECICI/wazuh-yml.tsv"
touch "$OC" "$AY" "$IY" "$FY" "$DY" "$WY"

OSSEC_CONF_OK=0
if duzlestir xml "$CONF" > "$OC"; then
  OSSEC_CONF_OK=1
  tamam M01 Manager "ossec.conf geçerli XML"
else
  : > "$OC"
  bulgu M01 Kritik Manager "ossec.conf okunamadı ya da XML hatalı" \
    "$(tail -n1 "$GECICI/py-hata.txt")" \
    "Hatalı XML ile manager yeniden başlatılınca açılmaz. Dosyayı düzeltip 'wazuh-analysisd -t' ile test et."
fi

# api.yaml çoğunlukla yorum satırıdır, boş gelmesi normal (varsayılanlar geçerli)
[[ -f $API_YAML ]] && { duzlestir yaml "$API_YAML" > "$AY" \
  || bilgi A00 API "api.yaml okunamadı" "$(tail -n1 "$GECICI/py-hata.txt")"; }
IX_KURULU=0
[[ -f $IX_YML ]] && { IX_KURULU=1; duzlestir yaml "$IX_YML" > "$IY" \
  || bilgi I00 Indexer "opensearch.yml okunamadı" "$(tail -n1 "$GECICI/py-hata.txt")"; }
[[ -f $FB_YML ]] && { duzlestir yaml "$FB_YML" > "$FY" \
  || bilgi F00 Filebeat "filebeat.yml okunamadı" "$(tail -n1 "$GECICI/py-hata.txt")"; }
[[ -f $DB_YML ]] && { duzlestir yaml "$DB_YML" > "$DY" \
  || bilgi D00 Dashboard "opensearch_dashboards.yml okunamadı" "$(tail -n1 "$GECICI/py-hata.txt")"; }
[[ -f $WZ_YML ]] && { duzlestir yaml "$WZ_YML" > "$WY" \
  || bilgi D00 Dashboard "wazuh.yml okunamadı" "$(tail -n1 "$GECICI/py-hata.txt")"; }

# Indexer adresi: parametre > yerel opensearch.yml > ossec.conf'taki <indexer>
if [[ -z $INDEXER_URL && $IX_KURULU -eq 1 ]]; then
  h=$(al "$IY" network.host)
  [[ -n $h ]] || h=$(al "$IY" network.host.0)
  [[ -z $h || $h == 0.0.0.0 || $h == _* ]] && h=127.0.0.1
  [[ $h == *:* ]] && h="[$h]"
  p=$(al "$IY" http.port)
  s=https
  evet "$(al "$IY" plugins.security.ssl.http.enabled)" || s=http
  INDEXER_URL="$s://$h:${p:-9200}"
fi
if [[ -z $INDEXER_URL ]]; then
  INDEXER_URL=$(hepsi "$OC" indexer/hosts/host | head -n1)
fi
INDEXER_URL="${INDEXER_URL%/}"

IX_SIFRE="${WAZUH_INDEXER_SIFRE:-}"
if [[ -n $INDEXER_URL && -z $IX_SIFRE && -t 0 ]]; then
  read -rsp "Indexer ($INDEXER_URL) '$INDEXER_KULLANICI' şifresi (atlamak için boş geç): " IX_SIFRE
  echo
fi

echo "Denetim başladı, birkaç saniye sürer..." >&2

# --- Manager ----------------------------------------------------------------

BL=Manager
if [[ $OSSEC_CONF_OK -eq 1 ]]; then

  # M02-M04 syscheck
  if ! yol_var_mi "$OC" '^syscheck/'; then
    bulgu M02 Orta $BL "syscheck bloğu yok" "ossec.conf'ta <syscheck> tanımlı değil" \
      "Manager'ın kendi dosyaları izlenmiyor. Varsayılan <syscheck> bloğunu geri ekle."
  elif evet "$(al "$OC" syscheck/disabled)"; then
    bulgu M02 Yüksek $BL "Dosya bütünlüğü izleme kapalı" "<syscheck><disabled>yes" \
      "<disabled>no</disabled> yap. Bu ayar sadece manager'ı etkiler; ajanlar için agent.conf'a bak."
  else
    tamam M02 $BL "Dosya bütünlüğü izleme açık"
    f=$(al "$OC" syscheck/frequency)
    if [[ $f =~ ^[0-9]+$ && $f -gt 86400 ]]; then
      bulgu M03 Düşük $BL "syscheck tarama sıklığı düşük" "frequency=$f sn ($((f / 3600)) saat)" \
        "Değişiklikler geç fark edilir. 43200 (12 saat) varsayılandır."
    else
      tamam M03 $BL "syscheck tarama sıklığı" "frequency=${f:-varsayılan}"
    fi
    if eslesen "$OC" '^syscheck/directories@(realtime|whodata)$' | grep -qi '^yes$'; then
      tamam M04 $BL "Gerçek zamanlı izlenen dizin var"
    else
      bilgi M04 $BL "Gerçek zamanlı izlenen dizin yok" \
        "Hiçbir <directories> realtime ya da whodata ile tanımlanmamış" \
        "Kritik dizinler (/etc, /usr/bin...) için realtime=\"yes\" düşün."
    fi
  fi

  # M05 SCA
  if ! yol_var_mi "$OC" '^sca/'; then
    bilgi M05 $BL "SCA bloğu yok" "<sca> tanımlı değil, varsayılan davranış geçerli"
  elif hayir "$(al "$OC" sca/enabled)"; then
    bulgu M05 Orta $BL "SCA kapalı" "<sca><enabled>no" \
      "CIS benzeri yapılandırma taramaları yapılmıyor. <enabled>yes</enabled> yap."
  else
    tamam M05 $BL "SCA açık"
  fi

  # M06 Syscollector
  if ! yol_var_mi "$OC" '^wodle\[syscollector\]/'; then
    bulgu M06 Orta $BL "Syscollector bloğu yok" "<wodle name=\"syscollector\"> tanımlı değil" \
      "Zafiyet tespiti paket envanterine dayanır; bloğu geri ekle."
  elif evet "$(al "$OC" 'wodle[syscollector]/disabled')"; then
    bulgu M06 Yüksek $BL "Syscollector kapalı" "<wodle name=\"syscollector\"><disabled>yes" \
      "Envanter toplanmıyor, zafiyet tespiti çalışmaz. <disabled>no</disabled> yap."
  elif hayir "$(al "$OC" 'wodle[syscollector]/packages')"; then
    bulgu M06 Yüksek $BL "Syscollector paket envanteri kapalı" "<packages>no" \
      "Zafiyet tespiti paket listesine dayanır. <packages>yes</packages> yap."
  else
    tamam M06 $BL "Syscollector ve paket envanteri açık"
  fi

  # M07 Zafiyet tespiti
  if ! yol_var_mi "$OC" '^vulnerability-detection/'; then
    bulgu M07 Orta $BL "vulnerability-detection bloğu yok" "4.8+ zafiyet tespiti bloğu ossec.conf'ta yok" \
      "<vulnerability-detection><enabled>yes</enabled>... bloğunu ekle."
  elif hayir "$(al "$OC" vulnerability-detection/enabled)"; then
    bulgu M07 Yüksek $BL "Zafiyet tespiti kapalı" "<vulnerability-detection><enabled>no" \
      "<enabled>yes</enabled> yap."
  else
    tamam M07 $BL "Zafiyet tespiti açık"
    if hayir "$(al "$OC" vulnerability-detection/index-status)"; then
      bulgu M07 Düşük $BL "Zafiyet durumu indexer'a yazılmıyor" "<index-status>no" \
        "Dashboard'daki Vulnerability Detection ekranı boş kalır. <index-status>yes</index-status> yap."
    fi
  fi

  # M08 Eski blok
  if yol_var_mi "$OC" '^vulnerability-detector/'; then
    bulgu M08 Düşük $BL "Eski vulnerability-detector bloğu duruyor" \
      "4.8'den itibaren bu blok yok sayılıyor" \
      "Ayarları <vulnerability-detection> bloğuna taşıyıp eski bloğu sil, kafa karıştırmasın."
  else
    tamam M08 $BL "Eski vulnerability-detector bloğu yok"
  fi

  # M09 <indexer> bağlantısı
  if ! yol_var_mi "$OC" '^indexer/'; then
    bulgu M09 Yüksek $BL "<indexer> bloğu yok" "Manager'ın indexer bağlantısı tanımlı değil" \
      "Zafiyet tespiti ve envanter verisi indexer'a yazılamaz. <indexer> bloğunu ekle."
  elif hayir "$(al "$OC" indexer/enabled)"; then
    bulgu M09 Orta $BL "<indexer> bağlantısı kapalı" "<indexer><enabled>no" \
      "Zafiyet tespiti sonuçları indexer'a yazılmaz."
  else
    sorun=()
    while read -r h; do
      [[ -z $h ]] && continue
      [[ $h == http://* ]] && sorun+=("$h şifresiz (http)")
      [[ $h == *0.0.0.0* ]] && sorun+=("$h bağlanılacak adres değil, kurulumdan kalmış olabilir")
    done < <(hepsi "$OC" indexer/hosts/host)
    for d in $(hepsi "$OC" indexer/ssl/certificate_authorities/ca) \
             "$(al "$OC" indexer/ssl/certificate)" "$(al "$OC" indexer/ssl/key)"; do
      [[ -n $d && ! -r $d ]] && sorun+=("$d bulunamadı")
    done
    if [[ ${#sorun[@]} -gt 0 ]]; then
      bulgu M09 Orta $BL "<indexer> bağlantı ayarlarında sorun" "$(printf '%s; ' "${sorun[@]}")" \
        "Adresi indexer'ın gerçek IP/adı ile, https ve geçerli sertifika yollarıyla yaz."
    else
      tamam M09 $BL "<indexer> bağlantı ayarları" "$(hepsi "$OC" indexer/hosts/host | paste -sd, -)"
    fi
  fi

  # M10 logall
  if evet "$(al "$OC" global/logall)" || evet "$(al "$OC" global/logall_json)"; then
    boyut=$(du -sh "$OSSEC/logs/archives" 2>/dev/null | cut -f1)
    bilgi M10 $BL "Bütün olaylar arşivleniyor (logall)" "logs/archives boyutu: ${boyut:-?}" \
      "Bilerek açılmadıysa kapat; arşiv diski hızla doldurur."
  else
    tamam M10 $BL "logall kapalı"
  fi

  # M11 Alarm eşiği
  sev=$(al "$OC" alerts/log_alert_level)
  if [[ $sev =~ ^[0-9]+$ && $sev -ge 7 ]]; then
    bulgu M11 Orta $BL "Alarm eşiği yüksek" "log_alert_level=$sev" \
      "$sev altındaki kurallar alarm üretmez, önemli olaylar kaybolabilir. Varsayılan 3."
  elif [[ $sev =~ ^[0-9]+$ && $sev -gt 3 ]]; then
    bulgu M11 Düşük $BL "Alarm eşiği varsayılandan yüksek" "log_alert_level=$sev" "Varsayılan 3."
  else
    tamam M11 $BL "Alarm eşiği" "log_alert_level=${sev:-varsayılan}"
  fi

  # M12 Syslog alımı
  syslog_blok=0
  while read -r b; do
    syslog_blok=1
    port=$(awk -F'\t' -v b="$b" '$3==b && $1=="remote/port"{print $2}' "$OC")
    proto=$(awk -F'\t' -v b="$b" '$3==b && $1=="remote/protocol"{print $2}' "$OC")
    ips=$(awk -F'\t' -v b="$b" '$3==b && $1=="remote/allowed-ips"{print $2}' "$OC" | paste -sd, -)
    yer="port ${port:-514}/${proto:-udp}"
    if [[ -z $ips ]]; then
      bulgu M12 Orta $BL "Syslog alımında allowed-ips yok" "$yer" \
        "remoted bu bloğu kabul etmez; izin verilen kaynak ağları <allowed-ips> ile yaz."
    elif [[ $ips =~ (^|,)(0\.0\.0\.0/0|any)(,|$) ]]; then
      bulgu M12 Orta $BL "Syslog her kaynaktan kabul ediliyor" "$yer, allowed-ips: $ips" \
        "Herkes sahte log gönderebilir. Sadece log gönderen cihazların ağlarını yaz."
    else
      tamam M12 $BL "Syslog alımı sınırlı" "$yer, allowed-ips: $ips"
    fi
  done < <(awk -F'\t' '$1=="remote/connection" && $2=="syslog"{print $3}' "$OC")
  [[ $syslog_blok -eq 1 ]] || tamam M12 $BL "Syslog alımı tanımlı değil"

  # M13 Ajan kaydı
  if evet "$(al "$OC" auth/disabled)"; then
    tamam M13 $BL "authd kapalı" "Ajanlar elle kaydediliyor"
  elif evet "$(al "$OC" auth/use_password)"; then
    if [[ -s $OSSEC/etc/authd.pass ]]; then
      tamam M13 $BL "Ajan kaydı parola istiyor"
    else
      bilgi M13 $BL "Ajan kaydı parola istiyor ama authd.pass yok" \
        "Parola her açılışta rastgele üretilir ve ossec.log'a yazılır" \
        "Kalıcı bir parola için $OSSEC/etc/authd.pass oluştur (640 root:wazuh)."
    fi
  elif [[ -n $(al "$OC" auth/ssl_agent_ca) ]]; then
    tamam M13 $BL "Ajan kaydı sertifika istiyor" "ssl_agent_ca: $(al "$OC" auth/ssl_agent_ca)"
  else
    p=$(al "$OC" auth/port)
    bulgu M13 Orta $BL "Ajan kaydı herkese açık" "authd parola ya da sertifika istemiyor (port ${p:-1515})" \
      "1515'e erişebilen herkes ajan kaydedebilir. <use_password>yes</use_password> ve authd.pass kullan ya da portu güvenlik duvarıyla sınırla."
  fi

  # M14 Cluster
  if hayir "$(al "$OC" cluster/disabled)"; then
    key=$(al "$OC" cluster/key)
    dugum=$(hepsi "$OC" cluster/nodes/node | paste -sd, -)
    if [[ ${#key} -ne 32 ]]; then
      bulgu M14 Kritik $BL "Cluster anahtarı geçersiz" "Anahtar ${#key} karakter, 32 olmalı" \
        "openssl rand -hex 16 ile üret, bütün düğümlerde aynı olsun."
    elif [[ $dugum == *NODE_IP* || -z $dugum ]]; then
      bulgu M14 Yüksek $BL "Cluster düğüm adresi tanımsız" "nodes: ${dugum:-boş}" \
        "<node> içine master düğümün adresini yaz."
    else
      tamam M14 $BL "Cluster ayarları" "node_type=$(al "$OC" cluster/node_type), nodes: $dugum"
    fi
  else
    tamam M14 $BL "Cluster kapalı (tek düğüm)"
  fi

  # M15 E-posta
  if evet "$(al "$OC" global/email_notification)" && [[ -z $(al "$OC" global/smtp_server) ]]; then
    bulgu M15 Düşük $BL "E-posta bildirimi açık ama SMTP sunucusu yok" "global/smtp_server boş" \
      "<smtp_server> ve <email_to> yaz ya da <email_notification>no</email_notification> yap."
  else
    tamam M15 $BL "E-posta ayarları tutarlı"
  fi
fi

# M16 debug
LIO="$OSSEC/etc/local_internal_options.conf"
debug=$(grep -hE '^[[:space:]]*[A-Za-z_.]+debug[[:space:]]*=[[:space:]]*[1-9]' "$LIO" 2>/dev/null | tr -d ' ' | paste -sd, -)
if [[ -n $debug ]]; then
  bulgu M16 Düşük Manager "Debug ayarı açık" "local_internal_options.conf: $debug" \
    "Sorun giderme bittiyse kaldır; ossec.log hızla büyür ve performans düşer."
else
  tamam M16 Manager "Debug ayarı yok"
fi

# M17 ossec.log
LOG="$OSSEC/logs/ossec.log"
if [[ -r $LOG ]]; then
  satirlar=$(tail -n 5000 "$LOG" | grep -E ' (ERROR|CRITICAL): ')
  if [[ -n $satirlar ]]; then
    adet=$(wc -l <<<"$satirlar")
    seviye=Orta
    grep -q ' CRITICAL: ' <<<"$satirlar" && seviye=Yüksek
    ornek=$(sed -E 's/^[0-9/]+ [0-9:]+ //' <<<"$satirlar" | sort | uniq -c | sort -rn | head -n 3 \
      | sed -E 's/^ *([0-9]+) /\1x /')
    bulgu M17 "$seviye" Manager "ossec.log'da hata kayıtları var" \
      "Son 5000 satırda $adet ERROR/CRITICAL. En sık: $ornek" \
      "Mesajlara bak; çoğu yanlış ayar ya da bağlantı sorunudur."
  else
    tamam M17 Manager "ossec.log'da son 5000 satırda hata yok"
  fi
fi

# M18 Düşen olaylar
STATE="$OSSEC/var/run/wazuh-analysisd.state"
if [[ -r $STATE ]]; then
  dusen=$(awk -F"'" '/^events_dropped=/{print $2}' "$STATE")
  if [[ $dusen =~ ^[0-9]+$ && $dusen -gt 0 ]]; then
    bulgu M18 Yüksek Manager "analysisd olay düşürüyor" "events_dropped=$dusen (son yeniden başlatmadan beri)" \
      "Gelen olay hızı işlenebilenden fazla. CPU'yu, analysisd thread ayarlarını ve gürültülü kaynakları kontrol et."
  else
    tamam M18 Manager "analysisd olay düşürmüyor"
  fi
fi

# --- API --------------------------------------------------------------------

BL=API
api_https=1
if hayir "$(al "$AY" https.enabled)"; then
  api_https=0
  bulgu A01 Yüksek $BL "API HTTPS kapalı" "api.yaml: https.enabled: no" \
    "Parolalar ve token'lar açık metin gider. https.enabled: yes yap."
else
  tamam A01 $BL "API HTTPS açık"
fi

if evet "$(al "$AY" cors.enabled)"; then
  kaynak=$(al "$AY" cors.source_route)
  if [[ -z $kaynak || $kaynak == "*" ]]; then
    bulgu A02 Orta $BL "CORS her kaynağa açık" "cors.enabled: yes, source_route: ${kaynak:-* (varsayılan)}" \
      "source_route'u sadece dashboard adresiyle sınırla ya da CORS'u kapat."
  else
    tamam A02 $BL "CORS sınırlı" "source_route: $kaynak"
  fi
else
  tamam A02 $BL "CORS kapalı"
fi

istek=$(al "$AY" access.max_request_per_minute)
deneme=$(al "$AY" access.max_login_attempts)
if [[ $istek == 0 ]]; then
  bulgu A03 Düşük $BL "API istek sınırı kapalı" "max_request_per_minute: 0" "Varsayılan 300."
elif [[ $deneme =~ ^[0-9]+$ && $deneme -gt 50 ]]; then
  bulgu A03 Düşük $BL "Giriş denemesi sınırı gevşek" "max_login_attempts: $deneme" "Varsayılan 50."
else
  tamam A03 $BL "İstek ve giriş denemesi sınırları"
fi

case "$(al "$AY" logs.level)" in
  debug|debug2)
    bulgu A04 Düşük $BL "API log seviyesi debug" "logs.level: $(al "$AY" logs.level)" "info'ya çek." ;;
  *) tamam A04 $BL "API log seviyesi" ;;
esac

API_PORT=$(al "$AY" port)
API_URL="http://127.0.0.1:${API_PORT:-55000}"
[[ $api_https -eq 1 ]] && API_URL="https://127.0.0.1:${API_PORT:-55000}"

if [[ $PAROLA_DENE -eq 1 ]]; then
  acik=()
  ulasilamadi=0
  for kp in wazuh:wazuh wazuh-wui:wazuh-wui; do
    kod=$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 \
      -u "$kp" -X POST "$API_URL/security/user/authenticate" 2>/dev/null)
    [[ $kod == 200 ]] && acik+=("${kp%%:*}")
    [[ $kod == 000 ]] && ulasilamadi=1
  done
  if [[ ${#acik[@]} -gt 0 ]]; then
    bulgu A05 Kritik $BL "API varsayılan parolayla açılıyor" "Kullanıcı: ${acik[*]}" \
      "Parolayı wazuh-passwords-tool.sh ile değiştir; wazuh-wui için dashboard'daki wazuh.yml'ı da güncelle."
  elif [[ $ulasilamadi -eq 1 ]]; then
    bilgi A05 $BL "API'ye bağlanılamadı" "$API_URL" "wazuh-manager servisi ve API portunu kontrol et."
  else
    tamam A05 $BL "API varsayılan parolaları kullanılmıyor"
  fi
fi

# --- Indexer ----------------------------------------------------------------

BL=Indexer
if [[ $IX_KURULU -eq 1 ]]; then
  if evet "$(al "$IY" plugins.security.allow_unsafe_democertificates)"; then
    bulgu I01 Yüksek $BL "Demo sertifikalara izin verilmiş" "plugins.security.allow_unsafe_democertificates: true" \
      "Demo sertifikaların özel anahtarları herkesin elinde. Kendi sertifikalarını üretip bu ayarı false yap."
  else
    tamam I01 $BL "Demo sertifika izni kapalı"
  fi

  if evet "$(al "$IY" plugins.security.ssl.http.enabled)"; then
    tamam I02 $BL "HTTP katmanında TLS açık"
  else
    bulgu I02 Yüksek $BL "HTTP katmanında TLS kapalı" "plugins.security.ssl.http.enabled: $(al "$IY" plugins.security.ssl.http.enabled)" \
      "9200 portunda parolalar açık metin gider. true yap."
  fi

  # I03 JVM heap: jvm.options.d altındakiler ana dosyayı ezer
  xms="" xmx=""
  while read -r satir; do
    [[ $satir == -Xms* ]] && xms="${satir#-Xms}"
    [[ $satir == -Xmx* ]] && xmx="${satir#-Xmx}"
  done < <(cat /etc/wazuh-indexer/jvm.options /etc/wazuh-indexer/jvm.options.d/*.options 2>/dev/null \
           | sed -E 's/^[[:space:]]+//' | grep -E '^-Xm[sx]')
  ram=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)
  if [[ -n $xmx ]]; then
    xms_mb=$(mb "$xms") xmx_mb=$(mb "$xmx")
    detay="Xms=$xms, Xmx=$xmx, RAM=${ram} MB"
    if [[ $xms_mb -ne $xmx_mb ]]; then
      bulgu I03 Orta $BL "JVM heap Xms ve Xmx farklı" "$detay" "İkisini aynı değere ayarla."
    elif [[ $xmx_mb -gt 32768 ]]; then
      bulgu I03 Orta $BL "JVM heap 32 GB'tan büyük" "$detay" \
        "32 GB üstünde sıkıştırılmış işaretçiler kapanır, fazla bellek boşa gider. 31g yeterli."
    elif [[ $ram -gt 0 && $xmx_mb -gt $((ram / 2)) ]]; then
      bulgu I03 Orta $BL "JVM heap RAM'in yarısından fazla" "$detay" \
        "Kalanı işletim sisteminin dosya önbelleğine ve (all-in-one ise) manager'a lazım. RAM'in yarısını geçme."
    else
      tamam I03 $BL "JVM heap boyutu" "$detay"
    fi
  else
    bilgi I03 $BL "JVM heap ayarı bulunamadı" "/etc/wazuh-indexer/jvm.options"
  fi

  mmc=$(sysctl -n vm.max_map_count 2>/dev/null)
  if [[ $mmc =~ ^[0-9]+$ && $mmc -lt 262144 ]]; then
    bulgu I04 Orta $BL "vm.max_map_count düşük" "vm.max_map_count=$mmc" \
      "262144 yap (/etc/sysctl.d/ altına yazıp sysctl --system)."
  else
    tamam I04 $BL "vm.max_map_count" "${mmc:-?}"
  fi
fi

if [[ -n $INDEXER_URL && $PAROLA_DENE -eq 1 ]]; then
  acik=()
  ulasilamadi=0
  for kp in admin:admin kibanaserver:kibanaserver; do
    kod=$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 \
      -u "$kp" "$INDEXER_URL/" 2>/dev/null)
    [[ $kod == 200 ]] && acik+=("${kp%%:*}")
    [[ $kod == 000 ]] && ulasilamadi=1
  done
  if [[ ${#acik[@]} -gt 0 ]]; then
    bulgu I05 Kritik $BL "Indexer varsayılan parolayla açılıyor" "Kullanıcı: ${acik[*]} ($INDEXER_URL)" \
      "wazuh-passwords-tool.sh ile bütün iç kullanıcıların parolalarını değiştir."
  elif [[ $ulasilamadi -eq 1 ]]; then
    bilgi I05 $BL "Indexer'a bağlanılamadı" "$INDEXER_URL"
  else
    tamam I05 $BL "Indexer varsayılan parolaları kullanılmıyor"
  fi
fi

# I06-I12 Indexer API
# Yanıt gövdesi $GECICI/ix.json'a, HTTP kodu IX_KOD'a yazılır. Yerel ya da iç ağdaki
# indexer'a gidiyoruz, sertifika adı çoğu zaman IP'yle uyuşmadığı için -k kullanılıyor.
ix_istek() {
  IX_KOD=$(printf 'user = "%s:%s"\n' "$(curl_kacir "$INDEXER_KULLANICI")" "$(curl_kacir "$IX_SIFRE")" \
    | curl -sk -K - --connect-timeout 10 --max-time 60 -o "$GECICI/ix.json" -w '%{http_code}' \
      "$INDEXER_URL$1" 2>/dev/null) || IX_KOD=000
  [[ $IX_KOD == 200 ]] || return 1
  duzlestir json "$GECICI/ix.json" > "$GECICI/ix.tsv"
}

IX_API="atlandı"
if [[ -n $INDEXER_URL && -n $IX_SIFRE ]]; then
  if ! ix_istek "/_cluster/health"; then
    bilgi I06 $BL "Indexer API'sine bağlanılamadı" "$INDEXER_URL, HTTP $IX_KOD, kullanıcı $INDEXER_KULLANICI" \
      "Adresi (-i), kullanıcıyı (-U) ve şifreyi kontrol et."
  else
    IX_API="yapıldı"
    H="$GECICI/health.tsv"
    cp "$GECICI/ix.tsv" "$H"
    durum=$(al "$H" status)
    dugum=$(al "$H" number_of_data_nodes)
    atanmamis=$(al "$H" unassigned_shards)
    aktif=$(al "$H" active_shards)
    detay="status=$durum, veri düğümü=$dugum, aktif shard=$aktif, atanmamış shard=$atanmamis"

    case "$durum" in
      green) tamam I06 $BL "Cluster sağlığı green" "$detay" ;;
      yellow)
        oneri="Atanmamış replika shard'ları var."
        [[ $dugum == 1 ]] && oneri="Tek düğümde replika atanamaz. Şablonda ve mevcut indekslerde index.number_of_replicas: 0 yap."
        bulgu I06 Orta $BL "Cluster sağlığı yellow" "$detay" "$oneri" ;;
      *)
        bulgu I06 Kritik $BL "Cluster sağlığı $durum" "$detay" \
          "Birincil shard'lar atanamıyor, veri yazılamıyor olabilir. GET _cluster/allocation/explain ile nedenine bak." ;;
    esac

    # I07 shard sınırı
    if ix_istek "/_cluster/settings?include_defaults=true&flat_settings=true"; then
      sinir=""
      for kat in persistent transient defaults; do
        sinir=$(al "$GECICI/ix.tsv" "$kat.cluster.max_shards_per_node")
        [[ -n $sinir ]] && break
      done
      sinir=${sinir:-1000}
      if [[ $dugum =~ ^[0-9]+$ && $dugum -gt 0 && $aktif =~ ^[0-9]+$ ]]; then
        toplam_sinir=$((sinir * dugum))
        oran=$((aktif * 100 / toplam_sinir))
        detay="$aktif / $toplam_sinir shard (%$oran), max_shards_per_node=$sinir"
        if [[ $oran -ge 90 ]]; then
          bulgu I07 Yüksek $BL "Shard sınırına çok yakın" "$detay" \
            "Sınıra gelince yeni günlük indeksler açılamaz, alarmlar yazılmaz. Eski indeksleri sil ya da ISM ile sınırla."
        elif [[ $oran -ge 75 ]]; then
          bulgu I07 Orta $BL "Shard sayısı sınıra yaklaşıyor" "$detay" \
            "ISM saklama süresini kısalt ya da tek düğümde replika sayısını 0 yap."
        else
          tamam I07 $BL "Shard sayısı" "$detay"
        fi
      fi
    fi

    # I08 Disk
    if ix_istek "/_cat/allocation?format=json&bytes=gb"; then
      disk_sorun=0
      while IFS=$'\t' read -r ad yuzde kullanilan toplam; do
        [[ $yuzde =~ ^[0-9]+$ ]] || continue
        detay="$ad: %$yuzde ($kullanilan / $toplam GB)"
        if [[ $yuzde -ge 95 ]]; then
          bulgu I08 Kritik $BL "Indexer diski flood-stage eşiğinde" "$detay" \
            "Indeksler salt okunur yapıldı ya da yapılmak üzere. Hemen yer aç."
        elif [[ $yuzde -ge 90 ]]; then
          bulgu I08 Yüksek $BL "Indexer diski high watermark'ta" "$detay" \
            "Bu düğüme yeni shard atanmıyor. Eski indeksleri sil ya da disk ekle."
        elif [[ $yuzde -ge 85 ]]; then
          bulgu I08 Orta $BL "Indexer diski low watermark'ta" "$detay" \
            "Bu düğüme yeni replika atanmıyor. Saklama süresini gözden geçir."
        else
          continue
        fi
        disk_sorun=1
      done < <(awk -F'\t' '{
          n = index($1, "."); i = substr($1, 1, n - 1); k = substr($1, n + 1)
          v[i, k] = $2; s[i] = 1
        } END {
          for (i in s) print v[i, "node"] "\t" v[i, "disk.percent"] "\t" v[i, "disk.used"] "\t" v[i, "disk.total"]
        }' "$GECICI/ix.tsv")
      [[ $disk_sorun -eq 1 ]] || tamam I08 $BL "Indexer disk doluluğu watermark altında"
    fi

    # I09 Salt okunur indeksler
    if ix_istek "/_all/_settings/index.blocks.*?flat_settings=true"; then
      kilitli=$(awk -F'\t' '$2=="true" && $1 ~ /\.settings\.index\.blocks\.(read_only_allow_delete|read_only|write)$/ {
          sub(/\.settings\.index\.blocks\..*$/, "", $1); print $1 }' "$GECICI/ix.tsv" | sort -u)
      if [[ -n $kilitli ]]; then
        bulgu I09 Kritik $BL "Yazmaya kapalı indeksler var" \
          "$(wc -l <<<"$kilitli") indeks: $(head -n 5 <<<"$kilitli" | paste -sd, -)" \
          "Genelde disk dolunca olur. Yer açtıktan sonra index.blocks.read_only_allow_delete'i null yap."
      else
        tamam I09 $BL "Yazmaya kapalı indeks yok"
      fi
    fi

    # I10 ISM
    if ix_istek "/_plugins/_ism/policies?size=1000"; then
      politika=$(awk -F'\t' '$1 ~ /ism_template(\.[0-9]+)?\.index_patterns\.[0-9]+$/ && $2 ~ /^wazuh-alerts/ {
          split($1, a, "."); print a[2] }' "$GECICI/ix.tsv" | sort -u)
      if [[ -n $politika ]]; then
        ids=$(while read -r n; do
            oncelik=$(eslesen "$GECICI/ix.tsv" "^policies\\.$n\\.policy\\.ism_template(\\.[0-9]+)?\\.priority\$" | head -n1)
            echo "$(al "$GECICI/ix.tsv" "policies.$n._id") (priority ${oncelik:-0})"
          done <<<"$politika" | paste -sd, -)
        if [[ $(wc -l <<<"$politika") -gt 1 ]]; then
          bulgu I10 Düşük $BL "wazuh-alerts'e birden fazla ISM politikası uyuyor" "$ids" \
            "Yeni indekse sadece priority'si en yüksek olan uygulanır, diğeri boşta kalır. Kullanılmayanı sil ya da desenini daralt."
        else
          tamam I10 $BL "wazuh-alerts için ISM politikası var" "$ids"
        fi
      else
        bulgu I10 Orta $BL "wazuh-alerts için saklama politikası yok" \
          "Hiçbir ISM politikası wazuh-alerts-* indekslerine otomatik uygulanmıyor" \
          "İndeksler sonsuza kadar birikir, disk ve shard sınırı dolar. ISM ile örneğin 90 gün sonra silen bir politika tanımla."
      fi
    else
      bilgi I10 $BL "ISM politikaları okunamadı" "HTTP $IX_KOD"
    fi

    # I11 Şablon
    ix_istek "/_template/wazuh"
    case "$IX_KOD" in
      200) tamam I11 $BL "wazuh indeks şablonu yüklü" ;;
      404) bulgu I11 Yüksek $BL "wazuh indeks şablonu yok" "GET _template/wazuh: 404" \
             "Alanlar yanlış tiplerle eşlenir, dashboard'da grafikler bozulur. Şablonu Filebeat ile yeniden yükle." ;;
      *)   bilgi I11 $BL "Şablon kontrol edilemedi" "HTTP $IX_KOD" ;;
    esac

    # I12 wazuh-alerts indeksleri
    if ix_istek "/_cat/indices/wazuh-alerts-*?format=json&h=index,store.size&s=index&bytes=mb"; then
      read -r adet ilk boyut < <(awk -F'\t' '
          $1 ~ /\.index$/ { n++; if (ilk == "") ilk = $2 }
          $1 ~ /\.store\.size$/ { t += $2 }
          END { printf "%d %s %.1f\n", n, (ilk == "" ? "-" : ilk), t / 1024 }' "$GECICI/ix.tsv")
      bilgi I12 $BL "wazuh-alerts indeksleri" "$adet indeks, toplam $boyut GB, en eskisi: $ilk"
    fi
  fi
elif [[ -n $INDEXER_URL ]]; then
  bilgi I06 $BL "Indexer API kontrolleri atlandı" "Şifre verilmedi" \
    "WAZUH_INDEXER_SIFRE ile ya da etkileşimli çalıştırıp şifreyi girerek I06-I12'yi de çalıştırabilirsin."
fi

# --- Filebeat ---------------------------------------------------------------

BL=Filebeat
if [[ -f $FB_YML ]]; then
  hostlar=$(eslesen "$FY" '^output\.elasticsearch\.hosts(\.[0-9]+)?$' | paste -sd, -)
  protokol=$(al "$FY" output.elasticsearch.protocol)
  sifreli=0
  [[ $protokol == https ]] && sifreli=1
  [[ -n $hostlar && $hostlar != *http://* && $hostlar == *https://* ]] && sifreli=1
  if [[ $sifreli -eq 1 ]]; then
    tamam F01 $BL "Indexer'a https ile bağlanıyor" "$hostlar"
  else
    bulgu F01 Yüksek $BL "Filebeat indexer'a şifresiz bağlanıyor" "hosts: ${hostlar:-?}, protocol: ${protokol:-yok}" \
      "output.elasticsearch.protocol: https yap ve ssl.certificate_authorities ver."
  fi

  if [[ $(al "$FY" output.elasticsearch.ssl.verification_mode) == none ]]; then
    bulgu F02 Orta $BL "Filebeat sertifika doğrulaması kapalı" "ssl.verification_mode: none" \
      "Araya giren biri alarmları okuyabilir. root-ca.pem'i verip verification_mode'u full yap."
  else
    tamam F02 $BL "Filebeat sertifika doğrulaması açık"
  fi

  alerts=$(eslesen "$FY" '^filebeat\.modules\.[0-9]+\.alerts\.enabled$' | head -n1)
  archives=$(eslesen "$FY" '^filebeat\.modules\.[0-9]+\.archives\.enabled$' | head -n1)
  if hayir "$alerts"; then
    bulgu F03 Kritik $BL "Alarmlar indexer'a gönderilmiyor" "wazuh modülü alerts.enabled: false" \
      "Dashboard'a hiçbir alarm düşmez. alerts.enabled: true yap."
  elif evet "$archives"; then
    bilgi F03 $BL "Arşiv de indexer'a gönderiliyor" "archives.enabled: true" \
      "Bütün olaylar indekslenir, disk çok hızlı dolar. Bilerek açılmadıysa kapat."
  else
    tamam F03 $BL "Filebeat modül ayarları"
  fi

  if command -v filebeat >/dev/null 2>&1; then
    if cikti=$(timeout 60 filebeat test output 2>&1); then
      tamam F04 $BL "filebeat test output başarılı"
    else
      bulgu F04 Yüksek $BL "Filebeat indexer'a bağlanamıyor" "$(tail -n 3 <<<"$cikti")" \
        "Alarmlar indexer'a gitmiyor. Adresi, sertifikaları ve keystore'daki kullanıcı/şifreyi kontrol et."
    fi
  fi
fi

# --- Dashboard --------------------------------------------------------------

BL=Dashboard
if [[ -f $DB_YML ]]; then
  if evet "$(al "$DY" server.ssl.enabled)"; then
    tamam D01 $BL "Dashboard HTTPS açık"
  else
    bulgu D01 Yüksek $BL "Dashboard HTTPS kapalı" "server.ssl.enabled: $(al "$DY" server.ssl.enabled)" \
      "Giriş bilgileri açık metin gider. server.ssl.enabled: true yap."
  fi
  if [[ $(al "$DY" opensearch.ssl.verificationMode) == none ]]; then
    bulgu D02 Orta $BL "Dashboard indexer sertifikasını doğrulamıyor" "opensearch.ssl.verificationMode: none" \
      "certificate ya da full yap, opensearch.ssl.certificateAuthorities ver."
  else
    tamam D02 $BL "Dashboard indexer sertifikasını doğruluyor"
  fi
fi
if [[ -f $WZ_YML ]]; then
  if eslesen "$WY" '^hosts\.[0-9]+\.[^.]+\.password$' | grep -qx 'wazuh-wui'; then
    bulgu D03 Yüksek $BL "wazuh.yml'da varsayılan API parolası" "$WZ_YML: password: wazuh-wui" \
      "wazuh-wui kullanıcısının parolasını değiştir ve bu dosyayı güncelle."
  else
    tamam D03 $BL "wazuh.yml'da varsayılan API parolası yok"
  fi
fi

# --- Sistem -----------------------------------------------------------------

BL=Sistem
if command -v systemctl >/dev/null 2>&1; then
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
    systemctl cat "$svc" >/dev/null 2>&1 || continue
    seviye=Yüksek
    [[ $svc == wazuh-manager ]] && seviye=Kritik
    if ! systemctl is-active --quiet "$svc"; then
      bulgu S01 "$seviye" $BL "$svc çalışmıyor" "systemctl is-active: $(systemctl is-active "$svc")" \
        "journalctl -u $svc ile nedenine bak."
    elif ! systemctl is-enabled --quiet "$svc"; then
      bulgu S01 Orta $BL "$svc açılışta başlamıyor" "systemctl is-enabled: $(systemctl is-enabled "$svc")" \
        "systemctl enable $svc"
    else
      tamam S01 $BL "$svc çalışıyor ve açılışta başlıyor"
    fi
  done
fi

# S02 Sürümler
MANAGER_SURUM=$(surum_kisa "$("$OSSEC/bin/wazuh-control" info -v 2>/dev/null)")
[[ -n $MANAGER_SURUM ]] || MANAGER_SURUM=$(paket_surum wazuh-manager)
surumler=()
[[ -n $MANAGER_SURUM ]] && surumler+=("manager=$MANAGER_SURUM")
for pkt in wazuh-indexer wazuh-dashboard; do
  v=$(paket_surum "$pkt")
  [[ -n $v ]] && surumler+=("${pkt#wazuh-}=$v")
done
if [[ ${#surumler[@]} -gt 1 ]]; then
  farkli=$(printf '%s\n' "${surumler[@]}" | cut -d= -f2 | sort -u | wc -l)
  farkli_minor=$(printf '%s\n' "${surumler[@]}" | cut -d= -f2 | cut -d. -f1,2 | sort -u | wc -l)
  if [[ $farkli_minor -gt 1 ]]; then
    bulgu S02 Orta $BL "Bileşen sürümleri uyumsuz" "${surumler[*]}" \
      "Wazuh bileşenleri aynı sürümde olmalı. Hepsini aynı sürüme yükselt."
  elif [[ $farkli -gt 1 ]]; then
    bulgu S02 Düşük $BL "Bileşenlerin yama sürümleri farklı" "${surumler[*]}" "Hepsini aynı sürüme getir."
  else
    tamam S02 $BL "Bileşen sürümleri aynı" "${surumler[*]}"
  fi
elif [[ ${#surumler[@]} -eq 1 ]]; then
  tamam S02 $BL "Sürüm" "${surumler[*]}"
fi
if [[ -n $MANAGER_SURUM ]] && [[ $(printf '%s\n4.8.0\n' "$MANAGER_SURUM" | sort -V | head -n1) != 4.8.0 ]]; then
  bilgi S02 $BL "Manager 4.8'den eski" "$MANAGER_SURUM" \
    "Script 4.8+ için yazıldı; zafiyet tespiti kontrolleri (M07-M09) bu sürümde geçerli değil."
fi

# S03 Disk
declare -A goruldu=()
dizinler=("$OSSEC")
if [[ $IX_KURULU -eq 1 ]]; then
  veri=$(al "$IY" path.data)
  [[ -n $veri ]] || veri=$(al "$IY" path.data.0)
  dizinler+=("${veri:-/var/lib/wazuh-indexer}")
fi
for d in "${dizinler[@]}"; do
  [[ -d $d ]] || continue
  read -r yuzde bagli < <(df -P "$d" | awk 'NR==2{gsub("%", "", $5); print $5, $6}')
  [[ $yuzde =~ ^[0-9]+$ ]] || continue
  [[ -n ${goruldu[$bagli]:-} ]] && continue
  goruldu[$bagli]=1
  detay="$d ($bagli): %$yuzde dolu"
  if [[ $yuzde -ge 90 ]]; then
    bulgu S03 Kritik $BL "Disk neredeyse dolu" "$detay" "Eski arşivleri ve indeksleri temizle ya da disk ekle."
  elif [[ $yuzde -ge 80 ]]; then
    bulgu S03 Yüksek $BL "Disk dolmak üzere" "$detay" "Saklama sürelerini gözden geçir."
  else
    tamam S03 $BL "Disk doluluğu" "$detay"
  fi
done

# S04 NTP
if command -v timedatectl >/dev/null 2>&1; then
  ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  if [[ $ntp == no ]]; then
    bulgu S04 Orta $BL "Saat senkronize değil" "timedatectl: NTPSynchronized=no" \
      "Alarm zamanları ve sertifika doğrulaması kayar. chrony ya da systemd-timesyncd'yi yapılandır."
  elif [[ $ntp == yes ]]; then
    tamam S04 $BL "Saat NTP ile senkronize"
  fi
fi

# S05 İzinler: herkese (others) okuma/yazma izni olmamalı
gizli=("$OSSEC/etc/ossec.conf" "$OSSEC/etc/client.keys" "$OSSEC/etc/authd.pass" "$OSSEC/etc/sslmanager.key"
       "$OSSEC/api/configuration/ssl/server.key" "$WZ_YML")
while IFS= read -r -d '' f; do gizli+=("$f"); done < <(
  find /etc/wazuh-indexer/certs /etc/filebeat/certs /etc/wazuh-dashboard/certs \
    -maxdepth 1 -type f \( -name '*key*' -o -name '*.key' \) -print0 2>/dev/null)
acik_dosya=()
for f in "${gizli[@]}"; do
  [[ -f $f ]] || continue
  izin=$(stat -c '%a' "$f")
  [[ ${izin: -1} != 0 ]] && acik_dosya+=("$f ($izin)")
done
if [[ ${#acik_dosya[@]} -gt 0 ]]; then
  bulgu S05 Yüksek $BL "Gizli dosyalar herkes tarafından okunabiliyor" "$(printf '%s, ' "${acik_dosya[@]}")" \
    "chmod o-rwx ile diğer kullanıcıların iznini kaldır."
else
  tamam S05 $BL "Anahtar ve gizli dosya izinleri"
fi

# S06 Portlar
if command -v ss >/dev/null 2>&1; then
  portlar=$(ss -tlnH 2>/dev/null | awk '{
      a = $4; p = a; sub(/.*:/, "", p)
      if (p ~ /^(1514|1515|1516|55000|9200|9300|443|5601)$/) print a }' | sort -u | paste -sd, -)
  bilgi S06 $BL "Dinlenen Wazuh portları" "${portlar:-yok}" \
    "0.0.0.0'da dinleyen portlara güvenlik duvarında sadece gereken ağlardan izin ver."
fi

# --- Sertifikalar -----------------------------------------------------------

BL=Sertifika
declare -A sertifika=()
sertifika_dizin=(/etc/wazuh-indexer/certs /etc/filebeat/certs /etc/wazuh-dashboard/certs
                 "$OSSEC/api/configuration/ssl" "$OSSEC/etc")
ek=()
for d in $(hepsi "$OC" indexer/ssl/certificate_authorities/ca) "$(al "$OC" indexer/ssl/certificate)"; do
  [[ -f $d ]] && ek+=("$d")
done
while IFS= read -r -d '' f; do
  grep -q 'BEGIN CERTIFICATE' "$f" 2>/dev/null || continue
  parmak=$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  [[ -n $parmak ]] || continue
  sertifika[$parmak]="${sertifika[$parmak]:+${sertifika[$parmak]}, }$f"
done < <({ find "${sertifika_dizin[@]}" -maxdepth 1 -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cert' \) \
             -print0 2>/dev/null; [[ ${#ek[@]} -gt 0 ]] && printf '%s\0' "${ek[@]}"; } | sort -zu)

simdi=$(date +%s)
saglam=0
for parmak in "${!sertifika[@]}"; do
  yollar="${sertifika[$parmak]}"
  f="${yollar%%, *}"
  bitis=$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)
  konu=$(openssl x509 -in "$f" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
  veren=$(openssl x509 -in "$f" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
  metin=$(openssl x509 -in "$f" -noout -text)
  kalan=$(( ($(date -d "$bitis" +%s) - simdi) / 86400 ))
  sorunlu=0

  # API ve authd sertifikalarını Wazuh kurulumda kendisi üretir (self-signed). Ajanlar ve
  # dashboard bunları varsayılan olarak doğrulamaz; süresi dolsa da bağlantı kopmaz.
  # Indexer, Filebeat ve dashboard sertifikaları ise karşılıklı doğrulanır.
  if [[ $f == "$OSSEC"/* ]]; then
    s_dolmus=Orta s_yakin=Düşük
    o_dolmus="Doğrulama açık değilse bağlantı kopmaz, ama ssl_verify_host / API sertifika doğrulaması açılınca sorun çıkar. Yeni sertifika üretip manager'ı yeniden başlat."
  else
    s_dolmus=Kritik s_yakin=Yüksek
    o_dolmus="Indexer, Filebeat ve dashboard birbirine bağlanamaz. Sertifikaları yenile."
  fi
  if [[ $kalan -lt 0 ]]; then
    bulgu C01 "$s_dolmus" $BL "Sertifikanın süresi dolmuş" "$konu, bitiş: $bitis ($((-kalan)) gün önce). Dosya: $yollar" \
      "$o_dolmus"
    sorunlu=1
  elif [[ $kalan -le $SERTIFIKA_GUN ]]; then
    bulgu C01 "$s_yakin" $BL "Sertifika yakında doluyor" "$konu, $kalan gün kaldı ($bitis). Dosya: $yollar" \
      "Dolmadan yenile."
    sorunlu=1
  fi

  bit=$(grep -oE 'Public-Key: \([0-9]+ bit' <<<"$metin" | grep -oE '[0-9]+')
  if grep -q 'rsaEncryption' <<<"$metin" && [[ ${bit:-0} -lt 2048 ]]; then
    bulgu C02 Orta $BL "Zayıf RSA anahtarı" "$konu: $bit bit. Dosya: $yollar" "En az 2048 bit ile yeniden üret."
    sorunlu=1
  fi
  if grep -m1 'Signature Algorithm' <<<"$metin" | grep -qi 'sha1'; then
    bulgu C02 Orta $BL "SHA-1 imzalı sertifika" "$konu. Dosya: $yollar" "SHA-256 ile yeniden üret."
    sorunlu=1
  fi

  if [[ $veren == *"Example Com Inc"* ]]; then
    bulgu C03 Yüksek $BL "OpenSearch demo sertifikası kullanılıyor" "$konu. Dosya: $yollar" \
      "Demo CA'nın özel anahtarı herkese açık. wazuh-certs-tool.sh ile kendi sertifikalarını üret."
    sorunlu=1
  fi
  [[ $sorunlu -eq 0 ]] && saglam=$((saglam + 1))
done
[[ $saglam -gt 0 ]] && tamam C01 $BL "Sorunsuz sertifikalar" "$saglam sertifika, $SERTIFIKA_GUN günden uzun süresi var"

# --- Çıktı ------------------------------------------------------------------

mkdir -p "$CIKTI" || hata "Çıktı klasörü oluşturulamadı: $CIKTI"

SIRALI="$GECICI/sirali.tsv"
awk -F'\t' 'BEGIN { r["Kritik"]=1; r["Yüksek"]=2; r["Orta"]=3; r["Düşük"]=4; r["Bilgi"]=5; r["Tamam"]=6 }
            { print r[$2] "\t" $0 }' "$BULGULAR" | sort -t $'\t' -s -k1,1n -k2,2 | cut -f2- > "$SIRALI"

awk -F'\t' -v d="$AYIRICI" '
  function q(s) { gsub(/"/, "\"\"", s); return "\"" s "\"" }
  BEGIN { print q("Kod") d q("Seviye") d q("Bileşen") d q("Bulgu") d q("Detay") d q("Öneri") }
  { print q($1) d q($2) d q($3) d q($4) d q($5) d q($6) }
' "$SIRALI" > "$CIKTI/bulgular.csv"

{
  echo "Wazuh yapılandırma denetimi"
  echo "Tarih    : $(date '+%Y-%m-%d %H:%M')"
  echo "Sunucu   : $(hostname)"
  echo "Manager  : ${MANAGER_SURUM:-?}"
  echo "Indexer  : ${INDEXER_URL:-yok} (API kontrolleri $IX_API)"
  echo
  awk -F'\t' '{ n[$2]++ } END {
      split("Kritik Yüksek Orta Düşük Bilgi Tamam", s, " ")
      printf "Sonuç:"
      for (i = 1; i <= 6; i++) printf "  %s: %d", s[i], n[s[i]]
      print ""
    }' "$SIRALI"
  echo
  if awk -F'\t' '$2 != "Tamam" { b = 1 } END { exit !b }' "$SIRALI"; then
    awk -F'\t' '$2 != "Tamam" {
        printf "[%s] %s  %s: %s\n", $2, $1, $3, $4
        if ($5 != "") printf "      %s\n", $5
        if ($6 != "") printf "      Öneri: %s\n", $6
      }' "$SIRALI"
  else
    echo "Bulgu yok."
  fi
  echo
  echo "Sorun bulunmayan kontrollerin listesi bulgular.csv'de (Seviye: Tamam)."
  echo "Dosyalar: $CIKTI/bulgular.csv, $CIKTI/ozet.txt"
} | tee "$CIKTI/ozet.txt"

awk -F'\t' '$2 ~ /^(Kritik|Yüksek|Orta|Düşük)$/ { b = 1 } END { exit b ? 2 : 0 }' "$SIRALI"
