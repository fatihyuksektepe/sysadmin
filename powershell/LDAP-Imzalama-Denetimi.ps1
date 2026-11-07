# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fatih Yüksektepe
#                      fatih@yuksektepe.org

<#
.SYNOPSIS
    LDAP imzalamayı zorunlu yapmadan önce imzasız LDAP bind yapan istemcileri bulur.

.DESCRIPTION
    Bütün DC'lerde "16 LDAP Interface Events" diagnostic logging seviyesini açar ya da
    kapatır ve bu sayede oluşan Event ID 2889 kayıtlarını toplar. 2889 her imzasız SASL
    bind ve şifresiz simple bind için istemcinin IP adresini ve kullandığı hesabı yazar.

    İşlemler:
      Durum   Her DC'de diagnostic seviyesini ve son 24 saatteki Event ID 2887 özetini
              gösterir. Hiçbir şeyi değiştirmez.
      Ac      Diagnostic seviyesini 2'ye çeker. -Onayla verilmezse sadece Durum gibi çalışır.
      Topla   Event ID 2889 kayıtlarını IP ve hesap bazında özetleyip CSV'ye yazar.
              Hiçbir şeyi değiştirmez.
      Kapat   Diagnostic seviyesini 0'a çeker. -Onayla verilmezse sadece Durum gibi çalışır.

    Sıra: Durum, Ac -Onayla, birkaç gün ya da hafta bekle, Topla, istemcileri düzelt,
    Kapat -Onayla. Event ID 2887 (günlük özet) varsayılan olarak her zaman açıktır ve
    Kapat'tan etkilenmez.

    Topla, olayları her DC'nin kendi üzerinde gruplar ve bu makineye sadece özet tabloyu
    getirir. Günde yüz binlerce 2889 üreten bir DC'de ham mesajları WinRM üzerinden
    taşımak çok uzun sürer ya da veri sınırına takılır.

    IP ve hesap, olay mesajının metninden değil olayın alanlarından okunur. Bu yüzden
    İngilizce olmayan Windows sürümlerinde de çalışır. IP adresindeki kaynak port atılır,
    aynı istemcinin bağlantıları tek satırda toplanır.

.PARAMETER Islem
    Durum, Ac, Topla ya da Kapat. Varsayılan: Durum.

.PARAMETER Onayla
    Ac ve Kapat için. Verilmezse DC'lerde hiçbir ayar değişmez.

.PARAMETER BaslangicZamani
    Topla için taramanın başlayacağı zaman. Varsayılan: 14 gün önce. Logging'i açtığın
    zamanı verirsen gereksiz yere eski kayıtlara bakılmaz.

.PARAMETER DCListe
    Taranacak DC'ler. Verilmezse Get-ADDomainController ile bulunur.

.PARAMETER CiktiKlasoru
    CSV'lerin yazılacağı klasör. Varsayılan: bulunulan klasör. Yoksa oluşturulur.

.EXAMPLE
    .\LDAP-Imzalama-Denetimi.ps1

.EXAMPLE
    .\LDAP-Imzalama-Denetimi.ps1 -Islem Ac -Onayla

.EXAMPLE
    .\LDAP-Imzalama-Denetimi.ps1 -Islem Topla -BaslangicZamani "2026-08-18 23:00" -DCListe dc01,dc02

.EXAMPLE
    .\LDAP-Imzalama-Denetimi.ps1 -Islem Kapat -Onayla

.NOTES
    Ac ve Kapat -Onayla ile çalıştırılırsa DC'lerde kayıt defteri değeri değiştirir:
    HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events
    Durum ve Topla salt okunurdur. LDAP imzalamayı hiçbir işlem zorunlu yapmaz.

    Gerekenler: PowerShell 5.1, bütün DC'lere WinRM erişimi, DC'lerde kayıt defteri ve
    Directory Service günlüğünü okuyabilen (Ac ve Kapat için yazabilen) bir hesap.
    -DCListe verilmezse RSAT ActiveDirectory modülü.

    Seviye 2 açıkken Directory Service günlüğü hızlı dolabilir. İş bitince Kapat'ı unutma.

    Script'i yönetim makinesinden ya da RDP ile girdiğin bir sunucudan çalıştır.
    Enter-PSSession gibi bir uzak oturumun içinden çalıştırılırsa DC'lere bağlanamaz
    (Kerberos double hop), her DC için HATA yazar.

    Yazar: Fatih Yüksektepe
           fatih@yuksektepe.org
    Sürüm: 0.1.0
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Durum', 'Ac', 'Topla', 'Kapat')]
    [string]$Islem = 'Durum',

    [switch]$Onayla,

    [datetime]$BaslangicZamani = (Get-Date).AddDays(-14),

    [string[]]$DCListe,

    [string]$CiktiKlasoru = (Get-Location).Path
)

if (-not (Test-Path $CiktiKlasoru)) {
    New-Item -ItemType Directory -Path $CiktiKlasoru -Force | Out-Null
}
$zamanEtiketi = Get-Date -Format yyyyMMdd_HHmmss

if (-not $DCListe) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DCListe = (Get-ADDomainController -Filter *).HostName
    }
    catch {
        Write-Host "HATA: ActiveDirectory modülü yüklenemedi ve -DCListe verilmedi. RSAT AD modülünü kur ya da DC'leri -DCListe ile ver." -ForegroundColor Red
        return
    }
}

Write-Host "DC sayısı: $($DCListe.Count)" -ForegroundColor Cyan

if ($Islem -ne 'Topla') {
    # Durum, Ac ve Kapat aynı okumayı yapar. Ac ve Kapat -Onayla ile değeri de yazar.
    $yeniDeger = switch ($Islem) { 'Ac' { 2 } 'Kapat' { 0 } default { $null } }
    $uygula = $Onayla.IsPresent -and $null -ne $yeniDeger

    $rapor = foreach ($dc in $DCListe) {
        Write-Host "`n$dc" -ForegroundColor Cyan
        try {
            $sonuc = Invoke-Command -ComputerName $dc -ScriptBlock {
                param($uygula, $yeniDeger)

                $yol = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
                $ad = '16 LDAP Interface Events'

                $once = (Get-ItemProperty -Path $yol -Name $ad -ErrorAction SilentlyContinue).$ad
                if ($null -eq $once) { $once = 0 }

                if ($uygula) {
                    Set-ItemProperty -Path $yol -Name $ad -Value $yeniDeger -Type DWord
                    $sonra = (Get-ItemProperty -Path $yol -Name $ad).$ad
                } else {
                    $sonra = $once
                }

                # 2887 günde bir yazılır ve son 24 saatte kaç imzasız bind olduğunu söyler.
                $olaylar = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Directory Service'
                    Id        = 2887
                    StartTime = (Get-Date).AddHours(-24)
                } -MaxEvents 5 -ErrorAction SilentlyContinue

                [pscustomobject]@{
                    SeviyeOnce = $once
                    SeviyeSonra = $sonra
                    Son24Saat2887 = ($olaylar | Measure-Object).Count
                    Son2887Mesaji = if ($olaylar) { $olaylar[0].Message -replace "`r`n", ' ' } else { 'Son 24 saatte 2887 kaydı yok' }
                }
            } -ArgumentList $uygula, $yeniDeger -ErrorAction Stop

            Write-Host "  Diagnostic seviyesi: $($sonuc.SeviyeOnce) -> $($sonuc.SeviyeSonra)"
            Write-Host "  Son 24 saatte 2887 kaydı: $($sonuc.Son24Saat2887)"

            [pscustomobject]@{
                DC            = $dc
                SeviyeOnce    = $sonuc.SeviyeOnce
                SeviyeSonra   = $sonuc.SeviyeSonra
                Son24Saat2887 = $sonuc.Son24Saat2887
                Son2887Mesaji = $sonuc.Son2887Mesaji
                Durum         = 'OK'
            }
        }
        catch {
            Write-Host "  HATA: $($_.Exception.Message)" -ForegroundColor Red
            [pscustomobject]@{
                DC            = $dc
                SeviyeOnce    = $null
                SeviyeSonra   = $null
                Son24Saat2887 = $null
                Son2887Mesaji = $null
                Durum         = "HATA: $($_.Exception.Message)"
            }
        }
    }

    $csv = Join-Path $CiktiKlasoru "LDAP-Imzalama-$($Islem)_$zamanEtiketi.csv"
    $rapor | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "`nCSV: $csv" -ForegroundColor Yellow

    if ($null -ne $yeniDeger -and -not $uygula) {
        Write-Host "Hiçbir DC'de ayar değişmedi. Değiştirmek için -Onayla ile tekrar çalıştır." -ForegroundColor Yellow
    }
    elseif ($Islem -eq 'Ac') {
        Write-Host "Diagnostic seviyesi 2'ye çekildi. Birkaç gün ya da hafta sonra -Islem Topla ile 2889 kayıtlarını topla." -ForegroundColor Green
        Write-Host "İstemciler düzeltilince -Islem Kapat -Onayla ile geri al." -ForegroundColor Yellow
    }
    elseif ($Islem -eq 'Kapat') {
        Write-Host "Diagnostic seviyesi 0'a çekildi." -ForegroundColor Green
    }
    return
}

# Topla
Write-Host "Tarih aralığı: $BaslangicZamani -> $(Get-Date)`n" -ForegroundColor Cyan

$ozet = New-Object System.Collections.Generic.List[object]
$hatalar = New-Object System.Collections.Generic.List[object]

$sira = 0
foreach ($dc in $DCListe) {
    $sira++
    Write-Host "[$sira/$($DCListe.Count)] $dc" -ForegroundColor Cyan
    $baslangicSaat = Get-Date

    try {
        $uzak = Invoke-Command -ComputerName $dc -ScriptBlock {
            param($baslangic)

            $olaylar = Get-WinEvent -FilterHashtable @{
                LogName   = 'Directory Service'
                Id        = 2889
                StartTime = $baslangic
            } -ErrorAction SilentlyContinue

            if (-not $olaylar) {
                return [pscustomobject]@{ ToplamKayit = 0; Ozet = @() }
            }

            # 2889 alanları: 0 istemci IP:port, 1 kimlik. Mesaj metni dile göre değişir, alanlar değişmez.
            $satirlar = foreach ($olay in $olaylar) {
                $ip = [string]$olay.Properties[0].Value
                if ($ip -match '^\[(.+)\]:\d+$') { $ip = $matches[1] }
                elseif ($ip -match '^([^:]+):\d+$') { $ip = $matches[1] }
                if (-not $ip) { $ip = 'Bilinmiyor' }

                $hesap = [string]$olay.Properties[1].Value
                if (-not $hesap) { $hesap = 'Bilinmiyor' }

                [pscustomobject]@{ IP = $ip; Hesap = $hesap; Zaman = $olay.TimeCreated }
            }

            $gruplar = $satirlar | Group-Object -Property IP, Hesap | ForEach-Object {
                $zamanlar = $_.Group.Zaman
                [pscustomobject]@{
                    IP         = $_.Group[0].IP
                    Hesap      = $_.Group[0].Hesap
                    Sayi       = $_.Count
                    IlkGorulme = ($zamanlar | Measure-Object -Minimum).Minimum
                    SonGorulme = ($zamanlar | Measure-Object -Maximum).Maximum
                }
            } | Sort-Object Sayi -Descending

            [pscustomobject]@{ ToplamKayit = $olaylar.Count; Ozet = $gruplar }
        } -ArgumentList $BaslangicZamani -ErrorAction Stop

        $sure = [math]::Round(((Get-Date) - $baslangicSaat).TotalSeconds, 1)

        if ($uzak.ToplamKayit -eq 0) {
            Write-Host "  2889 kaydı yok. ($sure sn)" -ForegroundColor Green
            continue
        }

        Write-Host "  2889 kaydı: $($uzak.ToplamKayit), farklı IP ve hesap: $($uzak.Ozet.Count) ($sure sn)" -ForegroundColor Yellow

        foreach ($s in $uzak.Ozet) {
            $ozet.Add([pscustomobject]@{
                DC         = $dc
                IP         = $s.IP
                Hesap      = $s.Hesap
                Sayi       = $s.Sayi
                IlkGorulme = $s.IlkGorulme
                SonGorulme = $s.SonGorulme
            })
        }
    }
    catch {
        Write-Host "  HATA: $($_.Exception.Message)" -ForegroundColor Red
        $hatalar.Add([pscustomobject]@{ DC = $dc; Hata = $_.Exception.Message })
    }
}

Write-Host ''

if ($ozet.Count -eq 0) {
    Write-Host "Bu tarih aralığında hiçbir DC'de Event ID 2889 kaydı yok." -ForegroundColor Green
    Write-Host "Diagnostic seviyesi bu süre boyunca 2 idiyse imzasız bind yapan istemci görülmedi." -ForegroundColor Green
}
else {
    $csv = Join-Path $CiktiKlasoru "LDAP-Imzasiz-Bind_$zamanEtiketi.csv"
    $ozet | Sort-Object DC, Sayi -Descending | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "CSV ($($ozet.Count) satır): $csv" -ForegroundColor Red

    Write-Host "`nDC başına en yoğun istemci:" -ForegroundColor Cyan
    $ozet | Group-Object DC | ForEach-Object {
        $enYogun = $_.Group | Sort-Object Sayi -Descending | Select-Object -First 1
        $toplam = ($_.Group | Measure-Object Sayi -Sum).Sum
        Write-Host ("  {0,-20} Toplam: {1,-8} En yoğun: {2} ({3}) x{4}" -f $_.Name, $toplam, $enYogun.Hesap, $enYogun.IP, $enYogun.Sayi)
    }

    Write-Host "`nLDAP imzalamayı zorunlu yapmadan önce bu istemcilerin LDAPS'e ya da imzalı SASL bind'e geçmesi gerekir." -ForegroundColor Yellow
}

if ($hatalar.Count -gt 0) {
    Write-Host "`nUYARI: Şu DC'lerden sonuç alınamadı, değerlendirme bu DC'ler için eksik:" -ForegroundColor Red
    $hatalar | ForEach-Object { Write-Host "  $($_.DC): $($_.Hata)" -ForegroundColor Red }
}
