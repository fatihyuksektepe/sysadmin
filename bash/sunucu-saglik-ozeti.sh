#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fatih Yüksektepe
#                      fatih@yuksektepe.org
#
# sunucu-saglik-ozeti.sh - Linux sunucunun genel durumunu tek ekranda gösterir
#
# SALT OKUNUR: hiçbir ayarı değiştirmez, paket kurmaz, servis yeniden başlatmaz.
#
# Kontroller:
#   S01  Doluluk oranı eşiği geçen dosya sistemleri
#   S02  Inode doluluğu eşiği geçen dosya sistemleri
#   S03  Bellek kullanımı (MemAvailable üzerinden)
#   S04  Swap kullanımı
#   S05  İşlemci başına düşen yük (1 dakikalık load average)
#   S06  Hata durumundaki systemd birimleri
#   S07  Bekleyen paket güncellemeleri (apt ya da dnf/yum, sadece yerel önbellek)
#   S08  Yeniden başlatma bekleyen sistem
#
# Gerekenler: bash, coreutils, awk. systemd, apt ve dnf varsa ilgili kontroller
# çalışır, yoksa atlanır. Root gerekmez.
#
# Kullanım:
#   ./sunucu-saglik-ozeti.sh
#   ./sunucu-saglik-ozeti.sh -d 90 -b 95 --guncelleme-atla
#
# Parametreler:
#   -d, --disk YUZDE       S01 eşiği (varsayılan: 85)
#   -i, --inode YUZDE      S02 eşiği (varsayılan: 85)
#   -b, --bellek YUZDE     S03 eşiği (varsayılan: 90)
#   -s, --swap YUZDE       S04 eşiği (varsayılan: 50)
#   -y, --yuk SAYI         S05 eşiği, işlemci başına (varsayılan: 1.5)
#       --guncelleme-atla  S07 kontrolünü yapma
#   -h, --help             Bu yardımı göster
#
# Çıkış kodları:
#   0  Bulgu yok
#   1  Hata (geçersiz parametre, Linux olmayan sistem)
#   2  En az bir bulgu var
# Cron ya da izleme sisteminden çağırıp sonuca göre uyarı üretebilirsin.
#
# Sürüm: 0.1.0

set -uo pipefail

DISK_ESIK=85
INODE_ESIK=85
BELLEK_ESIK=90
SWAP_ESIK=50
YUK_ESIK=1.5
GUNCELLEME=1
BULGU=0

# df çıktısında anlamı olmayan sanal dosya sistemleri
HARIC=(-x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs)

yardim() {
  sed -n '5,/^$/{s/^# \{0,1\}//;p;}' "$0"
}

hata() {
  echo "HATA: $*" >&2
  exit 1
}

sayi_mi() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--disk)         DISK_ESIK="${2:?--disk değer bekliyor}"; shift 2 ;;
    -i|--inode)        INODE_ESIK="${2:?--inode değer bekliyor}"; shift 2 ;;
    -b|--bellek)       BELLEK_ESIK="${2:?--bellek değer bekliyor}"; shift 2 ;;
    -s|--swap)         SWAP_ESIK="${2:?--swap değer bekliyor}"; shift 2 ;;
    -y|--yuk)          YUK_ESIK="${2:?--yuk değer bekliyor}"; shift 2 ;;
    --guncelleme-atla) GUNCELLEME=0; shift ;;
    -h|--help)         yardim; exit 0 ;;
    *)                 hata "Bilinmeyen parametre: $1 (yardım için -h)" ;;
  esac
done

for e in "$DISK_ESIK" "$INODE_ESIK" "$BELLEK_ESIK" "$SWAP_ESIK" "$YUK_ESIK"; do
  sayi_mi "$e" || hata "Eşik sayı olmalı: $e"
done

[[ "$(uname -s)" == "Linux" ]] || hata "Bu script sadece Linux'ta çalışır."

tamam() { printf '  [TAMAM]  %s  %s\n' "$1" "$2"; }
uyari() { printf '  [UYARI]  %s  %s\n' "$1" "$2"; BULGU=$((BULGU + 1)); }
atla()  { printf '  [ATLA ]  %s  %s\n' "$1" "$2"; }

# Genel bilgi
echo "Sunucu      : $(hostname)"
if [[ -r /etc/os-release ]]; then
  echo "Dağıtım     : $(. /etc/os-release && echo "${PRETTY_NAME:-bilinmiyor}")"
fi
echo "Çekirdek    : $(uname -r)"
echo "Açık kalma  : $(uptime -p 2>/dev/null || uptime)"
if command -v who >/dev/null 2>&1; then
  echo "Son açılış  : $(who -b 2>/dev/null | awk '{print $(NF-1), $NF}')"
fi
echo

# S01 disk doluluğu
satirlar=$(df -P "${HARIC[@]}" 2>/dev/null | awk -v e="$DISK_ESIK" 'NR > 1 { y = $5; sub(/%/, "", y); if (y + 0 >= e) printf "%s %%%s (%s)\n", $6, y, $1 }')
if [[ -n "$satirlar" ]]; then
  while IFS= read -r s; do uyari S01 "Disk dolu: $s"; done <<< "$satirlar"
else
  tamam S01 "Bütün dosya sistemleri %$DISK_ESIK altında"
fi

# S02 inode doluluğu (btrfs gibi inode sayısı vermeyen sistemler atlanır)
satirlar=$(df -P -i "${HARIC[@]}" 2>/dev/null | awk -v e="$INODE_ESIK" 'NR > 1 && $5 ~ /^[0-9]+%$/ { y = $5; sub(/%/, "", y); if (y + 0 >= e) printf "%s %%%s (%s)\n", $6, y, $1 }')
if [[ -n "$satirlar" ]]; then
  while IFS= read -r s; do uyari S02 "Inode dolu: $s"; done <<< "$satirlar"
else
  tamam S02 "Bütün dosya sistemlerinde inode %$INODE_ESIK altında"
fi

# S03 ve S04 bellek ve swap
read -r mem_top mem_bos swap_top swap_bos < <(awk '
  /^MemTotal:/     { mt = $2 }
  /^MemAvailable:/ { ma = $2 }
  /^SwapTotal:/    { st = $2 }
  /^SwapFree:/     { sf = $2 }
  END { print mt + 0, ma + 0, st + 0, sf + 0 }' /proc/meminfo)

if (( mem_top > 0 )); then
  mem_yuzde=$(( (mem_top - mem_bos) * 100 / mem_top ))
  mem_metin="%$mem_yuzde kullanımda ($(( mem_bos / 1024 )) MB boş / $(( mem_top / 1024 )) MB)"
  if awk -v y="$mem_yuzde" -v e="$BELLEK_ESIK" 'BEGIN { exit !(y >= e) }'; then
    uyari S03 "Bellek $mem_metin"
  else
    tamam S03 "Bellek $mem_metin"
  fi
else
  atla S03 "/proc/meminfo okunamadı"
fi

if (( swap_top > 0 )); then
  swap_yuzde=$(( (swap_top - swap_bos) * 100 / swap_top ))
  if awk -v y="$swap_yuzde" -v e="$SWAP_ESIK" 'BEGIN { exit !(y >= e) }'; then
    uyari S04 "Swap %$swap_yuzde kullanımda"
  else
    tamam S04 "Swap %$swap_yuzde kullanımda"
  fi
else
  atla S04 "Swap tanımlı değil"
fi

# S05 yük
cpu=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
yuk=$(awk '{print $1}' /proc/loadavg)
yuk_metin="Yük $yuk, $cpu işlemci"
if awk -v l="$yuk" -v c="$cpu" -v e="$YUK_ESIK" 'BEGIN { exit !(c > 0 && l / c >= e) }'; then
  uyari S05 "$yuk_metin (işlemci başına eşik $YUK_ESIK)"
else
  tamam S05 "$yuk_metin"
fi

# S06 systemd birimleri
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  birimler=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}')
  if [[ -n "$birimler" ]]; then
    while IFS= read -r b; do uyari S06 "Hata durumunda: $b"; done <<< "$birimler"
  else
    tamam S06 "Hata durumunda systemd birimi yok"
  fi
else
  atla S06 "systemd yok"
fi

# S07 bekleyen güncellemeler. Ağa çıkmaz, paket listesini yenilemez;
# sonuç en son apt update ya da dnf makecache zamanındaki önbelleğe göredir.
if (( GUNCELLEME == 0 )); then
  atla S07 "İstek üzerine atlandı"
elif command -v apt-get >/dev/null 2>&1; then
  adet=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ')
  if (( adet > 0 )); then
    uyari S07 "$adet paket güncelleme bekliyor (apt önbelleğine göre)"
  else
    tamam S07 "Bekleyen güncelleme yok (apt önbelleğine göre)"
  fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  pm=$(command -v dnf || command -v yum)
  liste=$("$pm" -q -C check-update 2>/dev/null)
  kod=$?
  if (( kod == 100 )); then
    adet=$(awk 'NF == 3 && $1 ~ /\./' <<< "$liste" | wc -l)
    uyari S07 "$adet paket güncelleme bekliyor ($(basename "$pm") önbelleğine göre)"
  elif (( kod == 0 )); then
    tamam S07 "Bekleyen güncelleme yok ($(basename "$pm") önbelleğine göre)"
  else
    atla S07 "$(basename "$pm") önbelleği okunamadı"
  fi
else
  atla S07 "apt ya da dnf bulunamadı"
fi

# S08 yeniden başlatma gereksinimi
if [[ -f /var/run/reboot-required ]]; then
  uyari S08 "Sistem yeniden başlatma bekliyor (/var/run/reboot-required)"
elif command -v needs-restarting >/dev/null 2>&1; then
  if needs-restarting -r >/dev/null 2>&1; then
    tamam S08 "Yeniden başlatma gerekmiyor"
  else
    uyari S08 "Sistem yeniden başlatma bekliyor (needs-restarting -r)"
  fi
elif command -v apt-get >/dev/null 2>&1; then
  tamam S08 "Yeniden başlatma gerekmiyor"
else
  atla S08 "Kontrol edilecek araç yok"
fi

echo
if (( BULGU > 0 )); then
  echo "Toplam $BULGU bulgu."
  exit 2
fi
echo "Bulgu yok."
exit 0
