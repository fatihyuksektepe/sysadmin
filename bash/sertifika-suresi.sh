#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fatih Yüksektepe
#                      fatih@yuksektepe.org
#
# sertifika-suresi.sh - TLS sertifikalarının bitiş tarihini kontrol eder
#
# Verilen sunuculara bağlanır, sunulan sertifikayı okur ve kaç gün kaldığını yazar.
# Süresi eşiğin altına inmiş, dolmuş ya da sunucu adıyla eşleşmeyen sertifikaları
# uyarı olarak gösterir. Zinciri güvenilir bir CA'ya bağlanmayan sertifikaları
# (kendinden imzalı, eksik ara sertifika) da uyarır.
# SALT OKUNUR: sadece TLS el sıkışması yapar.
#
# Gerekenler: bash, openssl. Linux ve macOS'ta çalışır.
#
# Kullanım:
#   ./sertifika-suresi.sh www.ornek.local mail.ornek.local:993
#   ./sertifika-suresi.sh -f sunucular.txt -g 45
#   ./sertifika-suresi.sh --starttls smtp mail.ornek.local:587
#
# Parametreler:
#   -f, --dosya DOSYA      Sunucu listesi, her satırda bir host[:port]
#                          (# ile başlayan ve boş satırlar atlanır)
#   -g, --gun N            Uyarı eşiği, gün (varsayılan: 30)
#   -t, --zaman-asimi SN   Bağlantı zaman aşımı, saniye (varsayılan: 10, timeout
#                          komutu varsa uygulanır)
#       --starttls PROTO   Bütün sunucular için STARTTLS kullan (smtp, imap, pop3,
#                          ftp, ldap, postgres, mysql ...; openssl s_client'ın
#                          desteklediği değerler)
#       --ca DOSYA         Zinciri doğrularken bu CA dosyasına da güven (iç CA için)
#   -h, --help             Bu yardımı göster
#
# Port verilmezse 443 kullanılır. IPv6 adresleri desteklenmez.
# Süre ve ad kontrolü sunucunun gönderdiği ilk sertifikaya (sunucu sertifikası)
# yapılır. Ara sertifikaların süresi ayrıca listelenmez, iptal durumu (CRL, OCSP)
# kontrol edilmez.
#
# Çıkış kodları:
#   0  Bulgu yok
#   1  Hata (geçersiz parametre, openssl yok, okunamayan dosya)
#   2  En az bir bulgu var (bağlanılamayan sunucu dahil)
# Cron ya da izleme sisteminden çağırıp sonuca göre uyarı üretebilirsin.
#
# Sürüm: 0.1.0

set -uo pipefail

GUN=30
ZAMAN_ASIMI=10
STARTTLS=""
CA_DOSYASI=""
DOSYA=""
HEDEFLER=()
BULGU=0

yardim() {
  sed -n '5,/^$/{s/^# \{0,1\}//;p;}' "$0"
}

hata() {
  echo "HATA: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--dosya)       DOSYA="${2:?--dosya değer bekliyor}"; shift 2 ;;
    -g|--gun)         GUN="${2:?--gun değer bekliyor}"; shift 2 ;;
    -t|--zaman-asimi) ZAMAN_ASIMI="${2:?--zaman-asimi değer bekliyor}"; shift 2 ;;
    --starttls)       STARTTLS="${2:?--starttls değer bekliyor}"; shift 2 ;;
    --ca)             CA_DOSYASI="${2:?--ca değer bekliyor}"; shift 2 ;;
    -h|--help)        yardim; exit 0 ;;
    -*)               hata "Bilinmeyen parametre: $1 (yardım için -h)" ;;
    *)                HEDEFLER+=("$1"); shift ;;
  esac
done

[[ "$GUN" =~ ^[0-9]+$ ]] || hata "Gün sayısı tam sayı olmalı: $GUN"
[[ "$ZAMAN_ASIMI" =~ ^[0-9]+$ ]] || hata "Zaman aşımı tam sayı olmalı: $ZAMAN_ASIMI"
command -v openssl >/dev/null 2>&1 || hata "openssl bulunamadı."
[[ -z "$CA_DOSYASI" || -r "$CA_DOSYASI" ]] || hata "CA dosyası okunamıyor: $CA_DOSYASI"

if [[ -n "$DOSYA" ]]; then
  [[ -r "$DOSYA" ]] || hata "Dosya okunamıyor: $DOSYA"
  while IFS= read -r satir || [[ -n "$satir" ]]; do
    satir="${satir%%#*}"
    satir="${satir//[[:space:]]/}"
    [[ -n "$satir" ]] && HEDEFLER+=("$satir")
  done < "$DOSYA"
fi

(( ${#HEDEFLER[@]} > 0 )) || hata "Kontrol edilecek sunucu yok (yardım için -h)"

ZAMANLAYICI=()
if command -v timeout >/dev/null 2>&1; then
  ZAMANLAYICI=(timeout "$ZAMAN_ASIMI")
fi

# openssl'in "Nov  7 12:00:00 2026 GMT" biçimindeki tarihini epoch'a çevirir.
# GNU date (Linux) ve BSD date (macOS) ayrı ayrı denenir.
epoch() {
  date -u -d "$1" +%s 2>/dev/null \
    || date -u -j -f "%b %e %T %Y %Z" "$1" +%s 2>/dev/null
}

# Sütunları karakter sayısına göre hizalar. printf genişliği bayt olarak
# saydığı için Türkçe karakterli değerlerde kayma olurdu.
doldur() {
  local metin="$1" genislik="$2" sag="${3:-0}" bosluk=""
  local fark=$(( genislik - ${#metin} ))
  (( fark > 0 )) && printf -v bosluk '%*s' "$fark" ""
  if (( sag )); then printf '%s%s' "$bosluk" "$metin"; else printf '%s%s' "$metin" "$bosluk"; fi
}

satir() {
  printf '%s %s %s  %s %s\n' "$(doldur "$1" 7)" "$(doldur "$2" 40)" "$(doldur "$3" 10 1)" "$(doldur "$4" 10)" "$5"
}

simdi=$(date -u +%s)

satir "DURUM" "SUNUCU" "KALAN" "BİTİŞ" "AÇIKLAMA"

for hedef in "${HEDEFLER[@]}"; do
  if [[ "$hedef" == *:* ]]; then
    host="${hedef%:*}"
    port="${hedef##*:}"
  else
    host="$hedef"
    port=443
  fi

  if [[ -z "$host" || ! "$port" =~ ^[0-9]+$ ]]; then
    satir "HATA" "$hedef" "-" "-" "Geçersiz host:port"
    BULGU=$((BULGU + 1))
    continue
  fi

  ip_mi=0
  [[ "$host" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && ip_mi=1

  secenek=(-connect "$host:$port")
  (( ip_mi == 0 )) && secenek+=(-servername "$host")
  [[ -n "$STARTTLS" ]] && secenek+=(-starttls "$STARTTLS")
  [[ -n "$CA_DOSYASI" ]] && secenek+=(-CAfile "$CA_DOSYASI")

  cikti=$("${ZAMANLAYICI[@]}" openssl s_client "${secenek[@]}" </dev/null 2>/dev/null)
  pem=$(openssl x509 2>/dev/null <<< "$cikti")
  dogrulama=$(sed -n 's/^ *Verify return code: //p' <<< "$cikti" | tail -n1)

  if [[ -z "$pem" ]]; then
    satir "HATA" "$host:$port" "-" "-" "Bağlanılamadı ya da sertifika alınamadı"
    BULGU=$((BULGU + 1))
    continue
  fi

  bitis_ham=$(openssl x509 -noout -enddate <<< "$pem" | cut -d= -f2-)
  cn=$(openssl x509 -noout -subject <<< "$pem" | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
  bitis_epoch=$(epoch "$bitis_ham")

  if [[ -z "$bitis_epoch" ]]; then
    satir "HATA" "$host:$port" "-" "-" "Bitiş tarihi okunamadı: $bitis_ham"
    BULGU=$((BULGU + 1))
    continue
  fi

  kalan_sn=$(( bitis_epoch - simdi ))
  if (( kalan_sn < 0 )); then
    kalan=$(( (kalan_sn - 86399) / 86400 ))
  else
    kalan=$(( kalan_sn / 86400 ))
  fi
  bitis=$(date -u -d "@$bitis_epoch" +%Y-%m-%d 2>/dev/null || date -u -r "$bitis_epoch" +%Y-%m-%d)

  notlar=()
  durum="TAMAM"
  if (( kalan_sn < 0 )); then
    durum="DOLMUŞ"
    notlar+=("Süresi dolmuş")
  elif (( kalan < GUN )); then
    durum="UYARI"
    notlar+=("$GUN günden az kaldı")
  fi

  # Ad kontrolü openssl 1.1 ve sonrasında var. Desteklenmiyorsa atlanır.
  if (( ip_mi == 1 )); then
    eslesme=$(openssl x509 -noout -checkip "$host" <<< "$pem" 2>/dev/null)
  else
    eslesme=$(openssl x509 -noout -checkhost "$host" <<< "$pem" 2>/dev/null)
  fi
  if [[ "$eslesme" == *"NOT match"* ]]; then
    [[ "$durum" == "TAMAM" ]] && durum="UYARI"
    notlar+=("Ad eşleşmiyor")
  fi

  # 0 zincir sağlam, 10 süre dolmuş (yukarıda zaten yazıldı)
  kod="${dogrulama%% *}"
  if [[ -n "$kod" && "$kod" != "0" && "$kod" != "10" ]]; then
    [[ "$durum" == "TAMAM" ]] && durum="UYARI"
    notlar+=("Zincir doğrulanamadı: $dogrulama")
  fi

  [[ "$durum" != "TAMAM" ]] && BULGU=$((BULGU + 1))

  aciklama="CN=${cn:-yok}"
  (( ${#notlar[@]} > 0 )) && aciklama="$(IFS=,; echo "${notlar[*]}" | sed 's/,/, /g'). $aciklama"

  satir "$durum" "$host:$port" "${kalan} gün" "$bitis" "$aciklama"
done

echo
if (( BULGU > 0 )); then
  echo "Toplam $BULGU bulgu."
  exit 2
fi
echo "Bulgu yok."
exit 0
