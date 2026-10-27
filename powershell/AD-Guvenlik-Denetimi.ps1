# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fatih Yüksektepe
#                      fatih@yuksektepe.org

<#
.SYNOPSIS
    Active Directory için genel güvenlik denetimi (SALT OKUNUR).

.DESCRIPTION
    Etki alanındaki yaygın güvenlik açıklarını tarar ve her kontrol için bir CSV,
    hepsi için de bir özet çıkarır. AD'de hiçbir şeyi değiştirmez; sadece okur.

    Kontroller:
      K01  Kerberoasting: SPN tanımlı etkin kullanıcı hesapları
      K02  AS-REP roasting: Kerberos ön doğrulaması kapalı hesaplar
      K03  Ayrıcalıklı gruplarda devre dışı hesaplar
      K04  Devre dışı kullanıcı hesapları
      K05  Uzun süredir giriş yapmayan etkin kullanıcılar
      K06  Hiç giriş yapmamış etkin kullanıcılar
      K07  Uzun süredir görülmeyen etkin bilgisayarlar
      K08  Parolası süresiz hesaplar
      K09  Parola gerektirmeyen hesaplar (PASSWD_NOTREQD)
      K10  Tersinir şifrelemeyle parola saklayan hesaplar
      K11  Parolası uzun süredir değişmeyen hesaplar
      K12  krbtgt parola yaşı
      K13  Ayrıcalıklı grup üyeleri (liste)
      K14  Boş olması gereken operatör grupları
      K15  Protected Users dışındaki / devredilebilir ayrıcalıklı hesaplar
      K16  adminCount=1 kalmış ama artık ayrıcalıklı olmayan hesaplar
      K17  Kısıtlamasız yetki devri (unconstrained delegation)
      K18  Protokol geçişli kısıtlı yetki devri
      K19  Kaynak tabanlı kısıtlı yetki devri (RBCD)
      K20  SIDHistory dolu hesaplar
      K21  Sadece DES kullanan hesaplar
      K22  Yerleşik Administrator hesabı
      K23  Guest hesabı
      K24  ms-DS-MachineAccountQuota
      K25  Varsayılan parola politikası
      K26  LAPS kapsamı
      K27  Desteği bitmiş eski işletim sistemleri (7, 8.1, Server 2003-2012...)
      K28  Pre-Windows 2000 Compatible Access üyeleri
      K29  AD Geri Dönüşüm Kutusu
      K30  Güven ilişkileri (SID filtreleme)

    ACL kontrolleri:
      K50  DCSync: çoğaltma hakkı olan beklenmedik hesaplar
      K51  Etki alanı kök nesnesinde beklenmedik yazma yetkisi
      K52  AdminSDHolder üzerinde beklenmedik yetkiler

    Ek kontroller:
      K53  Windows 10 (ESU / LTSC değilse destek dışı)
      K54  Zayıf ayrıntılı parola politikaları (FGPP) ve uygulandığı hesaplar
      K55  Ayrıcalıklı gruplarda gMSA, bilgisayar ve servis hesapları

    Sunucu protokol kontrolleri (DC'ler ve -EkSunucular):
      K31  Protokol ayarları okunamayan sunucular
      K32  TLS 1.0 / TLS 1.1 (SCHANNEL sunucu tarafı)
      K33  SMBv1 (sunucu ve istemci bileşeni)
      K34  SMB imzalama zorunlu değil
      K35  NTLMv1 kabul eden ya da gönderen sunucular (LmCompatibilityLevel)
      K36  NTLMv1 ile yapılan oturum açmalar (olay günlüğü, -NtlmV1OlayTara ile)
      K37  LDAP imzalama ve kanal bağlama (channel binding) zorunlu değil
      K38  İmzasız / düz metin LDAP bağlantıları (olay günlüğü, -LdapOlayTara ile)

    ADCS sertifika şablonları (AD'den okunur, CA'ya bağlanılmaz):
      K39  Yayındaki şablonlar (liste)
      K40  ESC1: istekte konu belirtilebilen, istemci kimlik doğrulamalı şablonlar
      K41  ESC2: her amaçlı ya da EKU'suz şablonlar
      K42  ESC3: kayıt aracısı (Certificate Request Agent) şablonları
      K43  ESC4: düşük yetkililerin değiştirebildiği şablonlar
      K44  ESC9: güvenlik uzantısı kapalı (CT_FLAG_NO_SECURITY_EXTENSION) şablonlar
      K45  ESC15: istekte konu belirtilebilen sürüm 1 şablonlar

    ADCS sertifika yetkilileri (her CA sunucusuna bağlanılır):
      K46  Kurumsal CA'lar (liste, yetkiler, web kaydı durumu)
      K47  ESC6: CA'da EDITF_ATTRIBUTESUBJECTALTNAME2 açık
      K48  ESC7: düşük yetkililerde ManageCA / ManageCertificates yetkisi
      K49  ESC8: NTLM kabul eden HTTP web kaydı (certsrv)

    Çıktı: CiktiKlasoru altında 00_Ozet.txt, 00_Bulgular.csv ve bulgu çıkan her
    kontrol için ayrı bir CSV. CSV ayırıcısı sistemin bölge ayarından alınır
    (Türkçe Windows'ta ';'), böylece Excel'de doğrudan açılır.

.PARAMETER Server
    Sorgulanacak DC ya da etki alanı. Boş bırakılırsa bulunduğun etki alanı kullanılır.

.PARAMETER InaktifGun
    Bu kadar gündür giriş yapmayan hesap "inaktif" sayılır. Varsayılan 90.

.PARAMETER ParolaYasGun
    Parolası bu kadar gündür değişmeyen hesap "eski parola" sayılır. Varsayılan 365.

.PARAMETER KrbtgtYasGun
    krbtgt parolası bundan eskiyse bulgu verilir. Varsayılan 180.

.PARAMETER CiktiKlasoru
    Raporların yazılacağı klasör. Varsayılan: bulunduğun dizinde
    AD_Guvenlik_Denetimi_<etki alanı>_<tarih_saat>.

.PARAMETER EkSunucular
    TLS / SMB / NTLM kontrollerinin DC'lere ek olarak yapılacağı sunucular.

.PARAMETER ProtokolKontrolleriniAtla
    Sunuculara bağlanan kontrolleri (K31-K38 ve K46-K49) çalıştırma, sadece AD'yi oku.

.PARAMETER NtlmV1OlayTara
    DC'lerin Security günlüğünde son -OlayGun gündeki NTLMv1 oturum açmalarını
    (olay 4624, LmPackageName = NTLM V1) arar ve kaynak IP / makine / hesap bazında özetler.
    NTLMv1'i kapatmadan önce onu kimin kullandığını bulmak için.

.PARAMETER LdapOlayTara
    DC'lerin Directory Service günlüğünde imzasız / düz metin LDAP bağlantılarını arar:
    2887 (günlük toplam sayı) ve tanılama günlüğü açıksa 2889 (istemci IP ve hesap).
    LDAP imzalamayı zorunlu yapmadan önce etkilenecek istemcileri bulmak için.

.PARAMETER OlayGun
    Olay günlüğü taramalarında (-NtlmV1OlayTara, -LdapOlayTara) geriye dönük gün sayısı.
    Varsayılan 7. Eski adı -NtlmOlayGun da çalışır.

.PARAMETER MaxOlay
    Her DC'den, her tarama için okunacak en fazla olay. Varsayılan 5000.
    Eski adı -NtlmMaxOlay da çalışır.

.EXAMPLE
    .\AD-Guvenlik-Denetimi.ps1

.EXAMPLE
    .\AD-Guvenlik-Denetimi.ps1 -NtlmV1OlayTara -LdapOlayTara -OlayGun 14 -EkSunucular fs01, sql01

.EXAMPLE
    .\AD-Guvenlik-Denetimi.ps1 -Server dc01.ornek.local -InaktifGun 60 -CiktiKlasoru C:\Temp\ADDenetim

.NOTES
    Gereksinimler: Windows PowerShell 5.1 veya PowerShell 7+, ActiveDirectory modülü (RSAT).
    Normal bir etki alanı kullanıcısı çoğu kontrolü çalıştırabilir; bazı öznitelikler
    yetkiye göre boş gelebilir. En doğru sonuç için Domain Admin ya da eşdeğer okuma
    yetkisiyle çalıştır.

    LastLogonDate, lastLogonTimestamp özniteliğinden gelir ve DC'ler arasında 9-14 gün
    gecikmeyle çoğalır. Bu yüzden inaktiflik kontrolleri gün hassasiyetinde değildir.

    Çok etki alanlı ormanlarda Enterprise Admins / Schema Admins üyelikleri sadece
    sorgulanan etki alanındaki hesaplar için görünür.

    K31-K36 her sunucuya önce WinRM (Invoke-Command), olmazsa uzak kayıt defteri ile
    bağlanır; ikisi için de hedefte yönetici yetkisi gerekir. NTLMv1 olay taraması uzak
    olay günlüğü (RPC) kullanır. Hiçbir ayar değiştirilmez.

    TLS ve SMB imzalama değerleri kayıt defterinde tanımlı değilse işletim sisteminin
    varsayılanı geçerlidir. Script, Windows Server 2025 (derleme 26100) öncesinde
    TLS 1.0/1.1'i varsayılan olarak açık kabul eder. WinRM ile bağlanılabildiğinde SMB
    değerleri Get-SmbServerConfiguration / Get-SmbClientConfiguration'dan alınır ve
    bunlar etkin değeri gösterir; uzak kayıt defterinde sadece tanımlı değer görülür.

    ADCS kontrollerinde "düşük yetkili" şunlardır: Everyone, Authenticated Users,
    Anonymous Logon, Users, Domain Users, Domain Computers. Manager Approval ya da yetkili
    imza (RA signature) isteyen şablonlar ESC1/2/3/15 için korumalı sayılır.

    ESC6 ve ESC7 CA sunucusunun kayıt defterinden okunur (WinRM, olmazsa uzak kayıt
    defteri) ve CA'da yönetici yetkisi ister. ESC8 için http(s)://<CA>/certsrv/ adresine
    kimlik bilgisi göndermeden istek atılır ve dönen WWW-Authenticate başlığına bakılır.
    HTTPS'te Extended Protection (EPA) açık mı dışarıdan anlaşılamaz; bu yüzden HTTPS
    üzerinde NTLM gören CA'lar "doğrula" notuyla listelenir. CES/CEP web servisleri
    kontrol edilmez.

    ACL kontrollerinde SYSTEM, Administrators, Domain Admins, Enterprise Admins ve DC grupları
    beklenen sayılır; Windows'un varsayılan olarak verdiği bilinen dar izinler (Key Admins'in
    msDS-KeyCredentialLink, Cert Publishers'ın userCertificate yazması gibi) atlanır. Sadece
    nesnenin kendisine uygulanan izin kayıtları değerlendirilir (InheritOnly olanlar değil).

    K24, MachineAccountQuota'nın gerçekten kullanılıp kullanılamadığını anlamak için DC OU'suna
    ve etki alanı köküne bağlı GPO'ların GptTmpl.inf dosyalarından "Add workstations to
    domain" (SeMachineAccountPrivilege) hakkını SYSVOL üzerinden okur. Bu hak düşük yetkili
    gruplardan alınmışsa kota sıfırdan büyük olsa da bulgu verilmez.

    Yazar: Fatih Yüksektepe
           fatih@yuksektepe.org
    Sürüm: 0.7.0
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [string]$Server,

    [ValidateRange(1, 3650)]
    [int]$InaktifGun = 90,

    [ValidateRange(1, 3650)]
    [int]$ParolaYasGun = 365,

    [ValidateRange(1, 3650)]
    [int]$KrbtgtYasGun = 180,

    [string]$CiktiKlasoru,

    [string[]]$EkSunucular = @(),

    [switch]$ProtokolKontrolleriniAtla,

    [switch]$NtlmV1OlayTara,

    [switch]$LdapOlayTara,

    [Alias('NtlmOlayGun')]
    [ValidateRange(1, 365)]
    [int]$OlayGun = 7,

    [Alias('NtlmMaxOlay')]
    [ValidateRange(1, 100000)]
    [int]$MaxOlay = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Simdi = Get-Date
$InaktifSinir = $Simdi.AddDays(-$InaktifGun)
$ParolaSinir = $Simdi.AddDays(-$ParolaYasGun)

$AdParam = @{}
if ($Server) { $AdParam.Server = $Server }

$Bulgular = New-Object System.Collections.Generic.List[object]

# Excel'in Türkçe karakterleri doğru açması için CSV'ler BOM'lu UTF-8 yazılır.
$CsvKodlama = 'UTF8'
if ($PSVersionTable.PSVersion.Major -ge 6) { $CsvKodlama = 'utf8BOM' }
$SeviyeSirasi = @{ KRITIK = 0; YUKSEK = 1; ORTA = 2; DUSUK = 3; BILGI = 4; HATA = 5; TAMAM = 6 }

# --- yardımcılar ---------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mesaj,

        [ValidateSet('BILGI', 'UYARI', 'HATA', 'DETAY')]
        [string]$Seviye = 'BILGI'
    )

    $satir = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Seviye, $Mesaj
    switch ($Seviye) {
        'HATA'  { Write-Host $satir -ForegroundColor Red }
        'UYARI' { Write-Warning $Mesaj }
        'DETAY' { Write-Verbose $Mesaj }
        default { Write-Host $satir }
    }
}

# StrictMode altında olmayan bir özelliğe erişmek hata verir; bu yüzden tek yerden okuyoruz.
function Get-Deger {
    param($Nesne, [string]$Ad)
    try { return $Nesne.$Ad } catch { return $null }
}

# Çok değerli öznitelikleri (SPN, SIDHistory...) her zaman dizi olarak döndürür.
function Get-Liste {
    param($Nesne, [string]$Ad)
    $v = Get-Deger $Nesne $Ad
    if ($null -ne $v) {
        foreach ($i in $v) {
            if ($null -ne $i -and "$i" -ne '') { "$i" }
        }
    }
}

function Format-Tarih {
    param($Tarih)
    if ($null -eq $Tarih) { return '' }
    return ([datetime]$Tarih).ToString('yyyy-MM-dd')
}

function Get-GunFarki {
    param($Tarih)
    if ($null -eq $Tarih) { return '' }
    return [int][math]::Floor(($Simdi - [datetime]$Tarih).TotalDays)
}

function ConvertTo-LdapDegeri {
    param([string]$Metin)
    $Metin.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
}

function Get-SifrelemeTurleri {
    param($Deger)
    if ($null -eq $Deger -or [int]$Deger -eq 0) { return 'Belirtilmemis (genelde RC4)' }
    $v = [int]$Deger
    $t = @()
    if ($v -band 0x3)  { $t += 'DES' }
    if ($v -band 0x4)  { $t += 'RC4' }
    if ($v -band 0x8)  { $t += 'AES128' }
    if ($v -band 0x10) { $t += 'AES256' }
    if ($t.Count -eq 0) { return "Bilinmeyen ($v)" }
    return ($t -join ',')
}

function Test-AesVar {
    param($Deger)
    if ($null -eq $Deger) { return $false }
    return ([int]$Deger -band 0x18) -ne 0
}

function Get-Ayricalik {
    param([string]$DN)
    if ($Ayricaliklilar.ContainsKey($DN)) { return (($Ayricaliklilar[$DN] | Sort-Object -Unique) -join ', ') }
    return ''
}

function New-KullaniciSatiri {
    param($Kullanici, [System.Collections.IDictionary]$Ek)

    $satir = [ordered]@{
        SamAccountName   = $Kullanici.SamAccountName
        Ad               = $Kullanici.Name
        Etkin            = $Kullanici.Enabled
        Ayricalikli      = Get-Ayricalik $Kullanici.DistinguishedName
        SonGiris         = Format-Tarih (Get-Deger $Kullanici 'LastLogonDate')
        ParolaDegisim    = Format-Tarih (Get-Deger $Kullanici 'PasswordLastSet')
        ParolaYasiGun    = Get-GunFarki (Get-Deger $Kullanici 'PasswordLastSet')
        Olusturulma      = Format-Tarih (Get-Deger $Kullanici 'whenCreated')
        Aciklama         = Get-Deger $Kullanici 'Description'
    }
    if ($Ek) { foreach ($k in $Ek.Keys) { $satir[$k] = $Ek[$k] } }
    $satir['DN'] = $Kullanici.DistinguishedName
    [pscustomobject]$satir
}

function New-BilgisayarSatiri {
    param($Bilgisayar, [System.Collections.IDictionary]$Ek)

    $satir = [ordered]@{
        Ad              = $Bilgisayar.Name
        DNSAdi          = Get-Deger $Bilgisayar 'DNSHostName'
        Etkin           = $Bilgisayar.Enabled
        IsletimSistemi  = Get-Deger $Bilgisayar 'OperatingSystem'
        Surum           = Get-Deger $Bilgisayar 'OperatingSystemVersion'
        SonGiris        = Format-Tarih (Get-Deger $Bilgisayar 'LastLogonDate')
        Olusturulma     = Format-Tarih (Get-Deger $Bilgisayar 'whenCreated')
    }
    if ($Ek) { foreach ($k in $Ek.Keys) { $satir[$k] = $Ek[$k] } }
    $satir['DN'] = $Bilgisayar.DistinguishedName
    [pscustomobject]$satir
}

function Add-Bulgu {
    param(
        [Parameter(Mandatory = $true)][string]$Kod,
        [Parameter(Mandatory = $true)][string]$Baslik,
        [Parameter(Mandatory = $true)][string]$Seviye,
        [object[]]$Nesneler = @(),
        [string]$Aciklama = '',
        [string]$Oneri = ''
    )

    $Nesneler = @($Nesneler | Where-Object { $null -ne $_ })
    $adet = $Nesneler.Count
    $dosya = ''

    if ($adet -eq 0) {
        $Seviye = 'TAMAM'
    }
    else {
        $dosya = '{0}_{1}.csv' -f $Kod, (($Baslik -replace '[^\w]+', '_').Trim('_'))
        $Nesneler | Export-Csv -Path (Join-Path $CiktiKlasoru $dosya) -NoTypeInformation -Encoding $CsvKodlama -UseCulture
    }

    $Bulgular.Add([pscustomobject]@{
        Kod      = $Kod
        Seviye   = $Seviye
        Kontrol  = $Baslik
        Adet     = $adet
        Aciklama = $Aciklama
        Oneri    = $Oneri
        Dosya    = $dosya
    })

    $renk = switch ($Seviye) {
        'KRITIK' { 'Magenta' }
        'YUKSEK' { 'Red' }
        'ORTA'   { 'Yellow' }
        'DUSUK'  { 'Cyan' }
        'TAMAM'  { 'Green' }
        default  { 'Gray' }
    }
    Write-Host ('  {0}  {1,-7} {2,5}  {3}' -f $Kod, $Seviye, $adet, $Baslik) -ForegroundColor $renk
}

# Bir kontrol hata verirse diğerleri yine çalışsın.
function Invoke-Kontrol {
    param([string]$Kod, [string]$Baslik, [scriptblock]$Blok)
    try {
        & $Blok
    }
    catch {
        Write-Log -Seviye DETAY -Mesaj "$Kod hata: $($_.Exception.Message)"
        $Bulgular.Add([pscustomobject]@{
            Kod      = $Kod
            Seviye   = 'HATA'
            Kontrol  = $Baslik
            Adet     = 0
            Aciklama = "Kontrol çalıştırılamadı: $($_.Exception.Message)"
            Oneri    = 'Yetkiyi ve DC erişimini kontrol edip tekrar çalıştır.'
            Dosya    = ''
        })
        Write-Host ('  {0}  {1,-7} {2,5}  {3}' -f $Kod, 'HATA', '-', $Baslik) -ForegroundColor Red
    }
}

function Test-SemaOzniteligi {
    param([string]$Ad)
    $r = @(Get-ADObject @AdParam -SearchBase $SemaNC -LDAPFilter "(lDAPDisplayName=$Ad)" -ErrorAction SilentlyContinue)
    return $r.Count -gt 0
}

# DC'lere uygulanan GPO'larda "Add workstations to domain" (SeMachineAccountPrivilege) kimde?
# Etki alanı köküne ve Domain Controllers OU'suna bağlı GPO'ların GptTmpl.inf dosyaları SYSVOL'dan okunur.
# DC OU'sundaki GPO kökü ezer; kökte zorlanmış (enforced) bağlantı ise ikisini de ezer.
# Aynı katmanda birden çok GPO tanımlıyorsa hepsinin birleşimi alınır (temkinli taraf).
function Get-BilgisayarEklemeHakki {
    $bulunan = @()
    try {
        $kaplar = @(
            [pscustomobject]@{ DN = $Domain.DistinguishedName; Katman = 0 }
            [pscustomobject]@{ DN = $Domain.DomainControllersContainer; Katman = 1 }
        )
        foreach ($kap in $kaplar) {
            $o = Get-ADObject @AdParam -Identity $kap.DN -Properties gPLink
            $link = "$(Get-Deger $o 'gPLink')"
            foreach ($m in [regex]::Matches($link, '\[LDAP://([^;\]]+);(\d+)\]', 'IgnoreCase')) {
                $secenek = [int]$m.Groups[2].Value
                if ($secenek -band 1) { continue }   # bağlantı devre dışı
                $gpo = Get-ADObject @AdParam -Identity $m.Groups[1].Value -Properties displayName, gPCFileSysPath, flags
                if ((Get-Deger $gpo 'flags') -band 2) { continue }   # GPO'nun bilgisayar ayarları kapalı
                $inf = Join-Path (Get-Deger $gpo 'gPCFileSysPath') 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
                if (-not (Test-Path -LiteralPath $inf)) { continue }
                $satir = @(Get-Content -LiteralPath $inf | Where-Object { $_ -match '^\s*SeMachineAccountPrivilege\s*=' }) | Select-Object -First 1
                if (-not $satir) { continue }
                $sidler = @(($satir -split '=', 2)[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
                        $girdi = $_
                        if ($girdi.StartsWith('*')) { $girdi.Substring(1) }
                        else {
                            try { (New-Object System.Security.Principal.NTAccount($girdi)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
                            catch { $girdi }
                        }
                    })
                $katman = $kap.Katman
                if ($katman -eq 0 -and ($secenek -band 2)) { $katman = 2 }
                $bulunan += [pscustomobject]@{ Sidler = $sidler; Gpo = "$(Get-Deger $gpo 'displayName')"; Katman = $katman }
            }
        }
    }
    catch {
        return @{ Sidler = $null; Kaynak = ''; Hata = $_.Exception.Message }
    }

    if ($bulunan.Count -eq 0) { return @{ Sidler = $null; Kaynak = ''; Hata = $null } }
    $enUst = ($bulunan | Measure-Object -Property Katman -Maximum).Maximum
    $gecerli = @($bulunan | Where-Object { $_.Katman -eq $enUst })
    $sidler = @($gecerli | ForEach-Object { $_.Sidler } | Sort-Object -Unique)
    return @{ Sidler = $sidler; Kaynak = (($gecerli | ForEach-Object { $_.Gpo }) -join ', '); Hata = $null }
}

# --- sunucu protokol ayarları ---------------------------------------------

# Her sunucudan okunacak kayıt defteri değerleri (HKLM altında).
$SchannelYolu = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$KayitListesi = @(
    @{ Ad = 'Build';          Yol = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion';                  Deger = 'CurrentBuildNumber' }
    @{ Ad = 'TLS10Sunucu';    Yol = "$SchannelYolu\TLS 1.0\Server";                                  Deger = 'Enabled' }
    @{ Ad = 'TLS11Sunucu';    Yol = "$SchannelYolu\TLS 1.1\Server";                                  Deger = 'Enabled' }
    @{ Ad = 'TLS10Istemci';   Yol = "$SchannelYolu\TLS 1.0\Client";                                  Deger = 'Enabled' }
    @{ Ad = 'TLS11Istemci';   Yol = "$SchannelYolu\TLS 1.1\Client";                                  Deger = 'Enabled' }
    @{ Ad = 'Smb1Parametre';  Yol = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';     Deger = 'SMB1' }
    @{ Ad = 'Smb1Surucu';     Yol = 'SYSTEM\CurrentControlSet\Services\srv';                         Deger = 'Start' }
    @{ Ad = 'Smb1Istemci';    Yol = 'SYSTEM\CurrentControlSet\Services\mrxsmb10';                    Deger = 'Start' }
    @{ Ad = 'SunucuImza';     Yol = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';     Deger = 'RequireSecuritySignature' }
    @{ Ad = 'IstemciImza';    Yol = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Deger = 'RequireSecuritySignature' }
    @{ Ad = 'LmUyumluluk';    Yol = 'SYSTEM\CurrentControlSet\Control\Lsa';                          Deger = 'LmCompatibilityLevel' }
    @{ Ad = 'LdapSunucuImza'; Yol = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters';             Deger = 'LDAPServerIntegrity' }
    @{ Ad = 'LdapKanalBag';   Yol = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters';             Deger = 'LdapEnforceChannelBinding' }
    @{ Ad = 'LdapTanilama';   Yol = 'SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics';            Deger = '16 LDAP Interface Events' }
    @{ Ad = 'LdapIstemciImza'; Yol = 'SYSTEM\CurrentControlSet\Services\LDAP';                       Deger = 'LDAPClientIntegrity' }
)

# Aynı blok hem WinRM ile hedefte, hem de uzak kayıt defteri için burada çalışır.
# UzakBilgisayar boşsa yerel kayıt defterini okur ve SMB cmdlet'lerini de dener.
$ProtokolOkuyucu = {
    param($Liste, $UzakBilgisayar)

    $sonuc = @{}
    if ($UzakBilgisayar) {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $UzakBilgisayar)
    }
    else {
        $hklm = [Microsoft.Win32.Registry]::LocalMachine
    }
    try {
        foreach ($k in $Liste) {
            $deger = $null
            $anahtar = $hklm.OpenSubKey($k.Yol)
            if ($anahtar) {
                $deger = $anahtar.GetValue($k.Deger, $null)
                $anahtar.Close()
            }
            $sonuc[$k.Ad] = $deger
        }
    }
    finally {
        if ($UzakBilgisayar) { $hklm.Close() }
    }

    $sonuc['CmdSmb1'] = $null
    $sonuc['CmdSunucuImza'] = $null
    $sonuc['CmdIstemciImza'] = $null
    if (-not $UzakBilgisayar) {
        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            try {
                $c = Get-SmbServerConfiguration -ErrorAction Stop
                $sonuc['CmdSmb1'] = [bool]$c.EnableSMB1Protocol
                $sonuc['CmdSunucuImza'] = [bool]$c.RequireSecuritySignature
            }
            catch { }
        }
        if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
            try {
                $sonuc['CmdIstemciImza'] = [bool](Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature
            }
            catch { }
        }
    }
    $sonuc
}

# Okuyucu blok param($Arguman, $UzakBilgisayar) almalı: WinRM'de hedefte $UzakBilgisayar
# boş çalışır, olmazsa burada uzak kayıt defteri için bilgisayar adıyla çalışır.
function Invoke-UzakOkuma {
    param([string]$Bilgisayar, [scriptblock]$Okuyucu, $Arguman)

    $opsiyon = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000
    try {
        $veri = Invoke-Command -ComputerName $Bilgisayar -SessionOption $opsiyon -ScriptBlock $Okuyucu `
            -ArgumentList $Arguman, $null -ErrorAction Stop
        return @{ Veri = $veri; Yontem = 'WinRM'; Hata = $null }
    }
    catch {
        $winrmHata = $_.Exception.Message
    }
    try {
        $veri = & $Okuyucu $Arguman $Bilgisayar
        return @{ Veri = $veri; Yontem = 'Uzak kayıt defteri'; Hata = $null }
    }
    catch {
        return @{ Veri = $null; Yontem = ''; Hata = "WinRM: $winrmHata | Kayıt defteri: $($_.Exception.Message)" }
    }
}

function Get-ProtokolAyarlari {
    param([string]$Bilgisayar)
    Invoke-UzakOkuma -Bilgisayar $Bilgisayar -Okuyucu $ProtokolOkuyucu -Arguman $KayitListesi
}

# CA yapılandırması: etkin ilke modülü, EditFlags ve CA güvenlik tanımlayıcısı (ikili).
$CaOkuyucu = {
    param($CaAdi, $UzakBilgisayar)

    if ($UzakBilgisayar) {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $UzakBilgisayar)
    }
    else {
        $hklm = [Microsoft.Win32.Registry]::LocalMachine
    }
    try {
        $kok = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaAdi"
        $anahtar = $hklm.OpenSubKey($kok)
        if (-not $anahtar) { throw "CertSvc yapılandırması bulunamadı: $kok" }
        $guvenlik = $anahtar.GetValue('Security', $null)
        $anahtar.Close()

        $etkin = 'CertificateAuthority_MicrosoftDefault.Policy'
        $pm = $hklm.OpenSubKey("$kok\PolicyModules")
        if ($pm) {
            $a = $pm.GetValue('Active', $null)
            if ($a) { $etkin = "$a" }
            $pm.Close()
        }
        $editFlags = $null
        $pol = $hklm.OpenSubKey("$kok\PolicyModules\$etkin")
        if ($pol) {
            $editFlags = $pol.GetValue('EditFlags', $null)
            $pol.Close()
        }
        @{ Guvenlik = $guvenlik; IlkeModulu = $etkin; EditFlags = $editFlags }
    }
    finally {
        if ($UzakBilgisayar) { $hklm.Close() }
    }
}

# Kimlik bilgisi göndermeden certsrv'ye istek atar; 401 + NTLM/Negotiate dönüyorsa relay'e açıktır.
function Test-WebKaydi {
    param([string]$Url)

    $istek = [System.Net.HttpWebRequest]::Create($Url)
    $istek.Method = 'GET'
    $istek.AllowAutoRedirect = $false
    $istek.Timeout = 10000
    $istek.UseDefaultCredentials = $false
    $yanit = $null
    try {
        $yanit = $istek.GetResponse()
    }
    catch [System.Net.WebException] {
        $yanit = $_.Exception.Response
        if (-not $yanit) { return @{ Durum = "Erişilemedi ($($_.Exception.Status))"; Ntlm = $false } }
    }
    try {
        $kod = [int]$yanit.StatusCode
        $dogrulama = @($yanit.Headers.GetValues('WWW-Authenticate'))
        $ntlm = @($dogrulama | Where-Object { $_ -match '^(NTLM|Negotiate)' }).Count -gt 0
        $yontemler = (@($dogrulama | ForEach-Object { ($_ -split ' ')[0] }) | Sort-Object -Unique) -join ', '
        if ($kod -eq 401) { return @{ Durum = "401 ($yontemler)"; Ntlm = $ntlm } }
        if ($kod -in 301, 302, 307, 308) { return @{ Durum = "Yönlendirme ($kod -> $($yanit.Headers['Location']))"; Ntlm = $false } }
        return @{ Durum = "HTTP $kod"; Ntlm = $false }
    }
    finally {
        $yanit.Close()
    }
}

function Get-SidAdi {
    param([string]$Sid)
    $dy = Get-Variable -Name DusukYetkililer -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($dy -and $dy.ContainsKey($Sid)) { return $dy[$Sid] }
    try { return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# Tanımlı değilse işletim sistemi varsayılanı; Server 2025 öncesinde TLS 1.0/1.1 açık.
function Get-TlsDurumu {
    param($Deger, [int]$Build)
    if ($null -eq $Deger) {
        if ($Build -ge 26100) { return @{ Acik = $false; Metin = 'Tanımsız (varsayılan kapalı)' } }
        return @{ Acik = $true; Metin = 'Tanımsız (varsayılan açık)' }
    }
    if ([int]$Deger -eq 0) { return @{ Acik = $false; Metin = 'Kapalı' } }
    return @{ Acik = $true; Metin = 'Açık' }
}

function ConvertTo-ProtokolSatiri {
    param([string]$Sunucu, [string]$Rol, [string]$IsletimSistemi, [hashtable]$Sonuc)

    $v = $Sonuc.Veri
    $build = 0
    if ($null -ne $v['Build']) { [void][int]::TryParse("$($v['Build'])", [ref]$build) }

    $tls10 = Get-TlsDurumu $v['TLS10Sunucu'] $build
    $tls11 = Get-TlsDurumu $v['TLS11Sunucu'] $build
    $tls10i = Get-TlsDurumu $v['TLS10Istemci'] $build
    $tls11i = Get-TlsDurumu $v['TLS11Istemci'] $build

    # SMBv1 sunucu: srv sürücüsü (SMB1 bileşeni) yoksa ya da devre dışıysa kapalıdır.
    $surucu = $v['Smb1Surucu']
    if ($null -eq $surucu) { $smb1 = $false; $smb1Metin = 'Bileşen yüklü değil' }
    elseif ([int]$surucu -eq 4) { $smb1 = $false; $smb1Metin = 'Sürücü devre dışı' }
    elseif ($null -ne $v['CmdSmb1']) { $smb1 = [bool]$v['CmdSmb1']; $smb1Metin = if ($smb1) { 'Açık' } else { 'Kapalı (SMB1=0)' } }
    elseif ($null -ne $v['Smb1Parametre'] -and [int]$v['Smb1Parametre'] -eq 0) { $smb1 = $false; $smb1Metin = 'Kapalı (SMB1=0)' }
    else { $smb1 = $true; $smb1Metin = 'Açık' }

    $istemci = $v['Smb1Istemci']
    if ($null -eq $istemci) { $smb1i = $false; $smb1iMetin = 'Bileşen yüklü değil' }
    elseif ([int]$istemci -eq 4) { $smb1i = $false; $smb1iMetin = 'Devre dışı' }
    else { $smb1i = $true; $smb1iMetin = 'Açık' }

    if ($null -ne $v['CmdSunucuImza']) { $sImza = [bool]$v['CmdSunucuImza'] }
    else { $sImza = ($null -ne $v['SunucuImza'] -and [int]$v['SunucuImza'] -eq 1) }
    if ($null -ne $v['CmdIstemciImza']) { $iImza = [bool]$v['CmdIstemciImza'] }
    else { $iImza = ($null -ne $v['IstemciImza'] -and [int]$v['IstemciImza'] -eq 1) }

    # Değer yoksa Vista/2008 sonrası varsayılan 3'tür.
    $lm = 3
    $lmMetin = 'Tanımsız (varsayılan 3)'
    if ($null -ne $v['LmUyumluluk']) { $lm = [int]$v['LmUyumluluk']; $lmMetin = "$lm" }
    $dc = $Rol -ne 'Ek sunucu'
    $ntlm = @()
    if ($lm -lt 3) { $ntlm += 'LM/NTLMv1 gönderiyor' }
    if ($dc -and $lm -lt 5) { $ntlm += 'NTLMv1 kabul ediyor' }

    # LDAP sunucu ayarları sadece DC'lerde anlamlı.
    # LDAPServerIntegrity: 1 = imza istenirse kullan (varsayılan), 2 = zorunlu.
    # LdapEnforceChannelBinding: 0 = asla (eski varsayılan), 1 = destekleniyorsa, 2 = her zaman.
    $ldapImza = $null; $ldapImzaMetin = ''
    $ldapKanal = $null; $ldapKanalMetin = ''
    $ldapTaniMetin = ''
    if ($dc) {
        if ($null -eq $v['LdapSunucuImza']) { $ldapImza = $false; $ldapImzaMetin = 'Tanımsız (varsayılan: zorunlu değil)' }
        elseif ([int]$v['LdapSunucuImza'] -ge 2) { $ldapImza = $true; $ldapImzaMetin = "Zorunlu ($($v['LdapSunucuImza']))" }
        else { $ldapImza = $false; $ldapImzaMetin = "Zorunlu değil ($($v['LdapSunucuImza']))" }

        if ($null -eq $v['LdapKanalBag']) { $ldapKanal = 0; $ldapKanalMetin = 'Tanımsız (varsayılan: asla)' }
        else {
            $ldapKanal = [int]$v['LdapKanalBag']
            $ldapKanalMetin = switch ($ldapKanal) { 0 { 'Asla (0)' } 1 { 'Destekleniyorsa (1)' } 2 { 'Her zaman (2)' } default { "Bilinmeyen ($ldapKanal)" } }
        }

        $tani = 0
        if ($null -ne $v['LdapTanilama']) { $tani = [int]$v['LdapTanilama'] }
        $ldapTaniMetin = if ($tani -ge 2) { "Açık ($tani)" } else { "Kapalı ($tani)" }
    }
    $ldapIstemciMetin = 'Tanımsız (varsayılan: 1, imza istenirse)'
    if ($null -ne $v['LdapIstemciImza']) {
        $ldapIstemciMetin = switch ([int]$v['LdapIstemciImza']) { 0 { 'Yok (0)' } 1 { 'İmza istenirse (1)' } 2 { 'Zorunlu (2)' } default { "Bilinmeyen ($($v['LdapIstemciImza']))" } }
    }

    [pscustomobject][ordered]@{
        Sunucu            = $Sunucu
        Rol               = $Rol
        IsletimSistemi    = $IsletimSistemi
        Build             = $build
        Yontem            = $Sonuc.Yontem
        TLS10Sunucu       = $tls10.Metin
        TLS11Sunucu       = $tls11.Metin
        TLS10Istemci      = $tls10i.Metin
        TLS11Istemci      = $tls11i.Metin
        TlsEskiAcik       = $tls10.Acik -or $tls11.Acik
        SMB1Sunucu        = $smb1Metin
        SMB1Istemci       = $smb1iMetin
        Smb1Acik          = $smb1 -or $smb1i
        SmbImzaSunucu     = if ($sImza) { 'Zorunlu' } else { 'Zorunlu değil' }
        SmbImzaIstemci    = if ($iImza) { 'Zorunlu' } else { 'Zorunlu değil' }
        SunucuImzaZorunlu = $sImza
        IstemciImzaZorunlu = $iImza
        LmCompatibilityLevel = $lmMetin
        NTLMv1            = $ntlm -join ', '
        LdapImza          = $ldapImzaMetin
        LdapKanalBaglama  = $ldapKanalMetin
        LdapTanilama      = $ldapTaniMetin
        LdapIstemciImza   = $ldapIstemciMetin
        LdapImzaZorunlu   = $ldapImza
        LdapKanalSeviye   = $ldapKanal
    }
}

function Get-LdapImzasizBaglantilar {
    param([string]$Bilgisayar)

    $filtre = @{ LogName = 'Directory Service'; Id = 2887, 2889; StartTime = $Simdi.AddDays(-$OlayGun) }
    try {
        $olaylar = @(Get-WinEvent -ComputerName $Bilgisayar -FilterHashtable $filtre -MaxEvents $MaxOlay -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
    $sinirDolu = $olaylar.Count -ge $MaxOlay

    # 2887: son 24 saatteki toplam; Properties[0] = imzasız SASL, [1] = düz metin simple bind.
    foreach ($o in @($olaylar | Where-Object { $_.Id -eq 2887 })) {
        [pscustomobject]@{
            DC          = $Bilgisayar
            Kaynak      = '2887 (günlük toplam)'
            IP          = ''
            Hesap       = ''
            BaglamaTuru = 'İmzasız SASL: {0}, düz metin simple bind: {1}' -f $o.Properties[0].Value, $o.Properties[1].Value
            Adet        = [int]$o.Properties[0].Value + [int]$o.Properties[1].Value
            SonGorulme  = $o.TimeCreated.ToString('yyyy-MM-dd HH:mm')
            SinirDolu   = $sinirDolu
        }
    }

    # 2889: tanılama açıksa her bağlantı; [0] = IP:port, [1] = hesap, [2] = 0 imzasız SASL / 1 simple bind.
    $istemciler = foreach ($o in @($olaylar | Where-Object { $_.Id -eq 2889 })) {
        $ip = "$($o.Properties[0].Value)"
        $ip = $ip -replace ':\d+$', ''
        [pscustomobject]@{
            Zaman = $o.TimeCreated
            IP    = $ip
            Hesap = "$($o.Properties[1].Value)"
            Tur   = if ("$($o.Properties[2].Value)" -eq '1') { 'Düz metin simple bind' } else { 'İmzasız SASL' }
        }
    }
    foreach ($g in @($istemciler) | Group-Object IP, Hesap, Tur) {
        $ilk = $g.Group[0]
        [pscustomobject]@{
            DC          = $Bilgisayar
            Kaynak      = '2889 (istemci)'
            IP          = $ilk.IP
            Hesap       = $ilk.Hesap
            BaglamaTuru = $ilk.Tur
            Adet        = $g.Count
            SonGorulme  = ($g.Group | Sort-Object Zaman -Descending | Select-Object -First 1).Zaman.ToString('yyyy-MM-dd HH:mm')
            SinirDolu   = $sinirDolu
        }
    }
}

function Get-NtlmV1Oturumlari {
    param([string]$Bilgisayar)

    $ms = [int64]$OlayGun * 86400000
    $xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]"
    try {
        $olaylar = @(Get-WinEvent -ComputerName $Bilgisayar -LogName Security -FilterXPath $xpath -MaxEvents $MaxOlay -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }

    $satirlar = foreach ($o in $olaylar) {
        $alan = @{}
        foreach ($d in ([xml]$o.ToXml()).Event.EventData.Data) { $alan[$d.Name] = $d.'#text' }
        [pscustomobject]@{
            Zaman     = $o.TimeCreated
            Hesap     = '{0}\{1}' -f $alan['TargetDomainName'], $alan['TargetUserName']
            Makine    = $alan['WorkstationName']
            IP        = $alan['IpAddress']
        }
    }

    foreach ($g in @($satirlar) | Group-Object Hesap, Makine, IP) {
        $ilk = $g.Group[0]
        [pscustomobject]@{
            DC        = $Bilgisayar
            Hesap     = $ilk.Hesap
            Makine    = $ilk.Makine
            IP        = $ilk.IP
            Adet      = $g.Count
            SonGorulme = ($g.Group | Sort-Object Zaman -Descending | Select-Object -First 1).Zaman.ToString('yyyy-MM-dd HH:mm')
            SinirDolu = $olaylar.Count -ge $MaxOlay
        }
    }
}

# --- veri toplama --------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false

    $Domain = Get-ADDomain @AdParam
    $Forest = Get-ADForest @AdParam
    $RootDSE = Get-ADRootDSE @AdParam
    $SemaNC = $RootDSE.schemaNamingContext
    $DomSid = $Domain.DomainSID.Value

    if (-not $CiktiKlasoru) {
        $CiktiKlasoru = Join-Path (Get-Location) ('AD_Guvenlik_Denetimi_{0}_{1}' -f $Domain.DNSRoot, $Simdi.ToString('yyyyMMdd_HHmmss'))
    }
    New-Item -ItemType Directory -Path $CiktiKlasoru -Force | Out-Null

    Write-Log "Etki alanı: $($Domain.DNSRoot)  (DC: $(if ($Server) { $Server } else { 'otomatik' }))"
    Write-Log "Çıktı klasörü: $CiktiKlasoru"

    $RootSid = $DomSid
    $RootServer = $Server
    if ($Forest.RootDomain -ne $Domain.DNSRoot) {
        try {
            $RootSid = (Get-ADDomain -Identity $Forest.RootDomain -Server $Forest.RootDomain).DomainSID.Value
            $RootServer = $Forest.RootDomain
        }
        catch {
            Write-Log -Seviye UYARI -Mesaj "Orman kök etki alanına ulaşılamadı ($($Forest.RootDomain)); Enterprise/Schema Admins atlanacak."
            $RootSid = $null
        }
    }

    Write-Log 'Kullanıcılar okunuyor...'
    $KullaniciOzellikleri = @(
        'Description', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired',
        'DoesNotRequirePreAuth', 'AllowReversiblePasswordEncryption', 'ServicePrincipalName',
        'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity', 'AccountNotDelegated', 'adminCount', 'SIDHistory',
        'msDS-SupportedEncryptionTypes', 'UseDESKeyOnly', 'whenCreated', 'PrimaryGroupID'
    )
    $Kullanicilar = @(Get-ADUser @AdParam -Filter * -Properties $KullaniciOzellikleri)

    Write-Log 'Bilgisayarlar okunuyor...'
    $LapsEski = Test-SemaOzniteligi 'ms-Mcs-AdmPwdExpirationTime'
    $LapsYeni = Test-SemaOzniteligi 'msLAPS-PasswordExpirationTime'
    $BilgisayarOzellikleri = @(
        'DNSHostName', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'whenCreated',
        'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity', 'PrimaryGroupID', 'SIDHistory'
    )
    if ($LapsEski) { $BilgisayarOzellikleri += 'ms-Mcs-AdmPwdExpirationTime' }
    if ($LapsYeni) { $BilgisayarOzellikleri += 'msLAPS-PasswordExpirationTime' }
    $Bilgisayarlar = @(Get-ADComputer @AdParam -Filter * -Properties $BilgisayarOzellikleri)

    # 516 = DC, 521 = salt okunur DC
    $DCler = @($Bilgisayarlar | Where-Object { (Get-Deger $_ 'PrimaryGroupID') -in 516, 521 })

    Write-Log "Kullanıcı: $($Kullanicilar.Count)  Bilgisayar: $($Bilgisayarlar.Count)  DC: $($DCler.Count)"

    # --- ayrıcalıklı gruplar ---------------------------------------------
    # Adlar dil ayarına göre değişebildiği için gruplar SID ile bulunuyor.
    Write-Log 'Ayrıcalıklı grup üyelikleri çözülüyor...'

    $AyricalikliGruplar = [ordered]@{
        'Domain Admins'               = @{ Sid = "$DomSid-512"; Sunucu = $Server }
        'Administrators'              = @{ Sid = 'S-1-5-32-544'; Sunucu = $Server }
        'Account Operators'           = @{ Sid = 'S-1-5-32-548'; Sunucu = $Server }
        'Server Operators'            = @{ Sid = 'S-1-5-32-549'; Sunucu = $Server }
        'Print Operators'             = @{ Sid = 'S-1-5-32-550'; Sunucu = $Server }
        'Backup Operators'            = @{ Sid = 'S-1-5-32-551'; Sunucu = $Server }
        'Group Policy Creator Owners' = @{ Sid = "$DomSid-520"; Sunucu = $Server }
        'Key Admins'                  = @{ Sid = "$DomSid-526"; Sunucu = $Server }
    }
    if ($RootSid) {
        $AyricalikliGruplar['Enterprise Admins']      = @{ Sid = "$RootSid-519"; Sunucu = $RootServer }
        $AyricalikliGruplar['Schema Admins']          = @{ Sid = "$RootSid-518"; Sunucu = $RootServer }
        $AyricalikliGruplar['Enterprise Key Admins']  = @{ Sid = "$RootSid-527"; Sunucu = $RootServer }
    }

    $Ayricaliklilar = @{}      # DN -> grup adları
    $GrupUyeleri = @{}         # grup adı -> üye nesneleri

    foreach ($grupAdi in @($AyricalikliGruplar.Keys)) {
        $tanim = $AyricalikliGruplar[$grupAdi]
        $p = @{}
        if ($tanim.Sunucu) { $p.Server = $tanim.Sunucu }
        try {
            $grup = Get-ADGroup @p -Identity $tanim.Sid
        }
        catch {
            Write-Log -Seviye DETAY -Mesaj "$grupAdi bulunamadı: $($_.Exception.Message)"
            continue
        }
        $filtre = '(&(memberOf:1.2.840.113556.1.4.1941:={0})(!(objectClass=group)))' -f (ConvertTo-LdapDegeri $grup.DistinguishedName)
        $uyeler = @(Get-ADObject @p -LDAPFilter $filtre -Properties sAMAccountName, objectClass)
        $GrupUyeleri[$grupAdi] = $uyeler
        foreach ($u in $uyeler) {
            if (-not $Ayricaliklilar.ContainsKey($u.DistinguishedName)) { $Ayricaliklilar[$u.DistinguishedName] = @() }
            $Ayricaliklilar[$u.DistinguishedName] += $grupAdi
        }
    }

    # DnsAdmins'in sabit bir RID'i yok, adıyla aranıyor.
    $dnsAdmins = @(Get-ADGroup @AdParam -Filter "Name -eq 'DnsAdmins'")
    if ($dnsAdmins.Count -gt 0) {
        $filtre = '(&(memberOf:1.2.840.113556.1.4.1941:={0})(!(objectClass=group)))' -f (ConvertTo-LdapDegeri $dnsAdmins[0].DistinguishedName)
        $uyeler = @(Get-ADObject @AdParam -LDAPFilter $filtre -Properties sAMAccountName, objectClass)
        $GrupUyeleri['DnsAdmins'] = $uyeler
        foreach ($u in $uyeler) {
            if (-not $Ayricaliklilar.ContainsKey($u.DistinguishedName)) { $Ayricaliklilar[$u.DistinguishedName] = @() }
            $Ayricaliklilar[$u.DistinguishedName] += 'DnsAdmins'
        }
    }

    # Birincil grubu Domain Admins olan hesaplar memberOf'ta görünmez.
    foreach ($u in $Kullanicilar | Where-Object { (Get-Deger $_ 'PrimaryGroupID') -eq 512 }) {
        if (-not $Ayricaliklilar.ContainsKey($u.DistinguishedName)) { $Ayricaliklilar[$u.DistinguishedName] = @() }
        $Ayricaliklilar[$u.DistinguishedName] += 'Domain Admins (birincil grup)'
    }

    $EtkinKullanicilar = @($Kullanicilar | Where-Object { $_.Enabled })
    $AyricalikliKullanicilar = @($Kullanicilar | Where-Object { $Ayricaliklilar.ContainsKey($_.DistinguishedName) })

    # Düşük yetkili sayılan gruplar (K24, ACL ve ADCS kontrollerinde kullanılır).
    $DusukYetkililer = @{
        'S-1-1-0'      = 'Everyone'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-7'      = 'Anonymous Logon'
        'S-1-5-32-545' = 'Users'
        "$DomSid-513"  = 'Domain Users'
        "$DomSid-515"  = 'Domain Computers'
    }
    if ($RootSid -and $RootSid -ne $DomSid) {
        $DusukYetkililer["$RootSid-513"] = 'Domain Users (kök)'
        $DusukYetkililer["$RootSid-515"] = 'Domain Computers (kök)'
    }

    Write-Host ''
    Write-Log 'Kontroller:'

    # --- kontroller --------------------------------------------------------

    Invoke-Kontrol 'K01' 'Kerberoasting' {
        $liste = foreach ($u in $EtkinKullanicilar) {
            if ($u.SamAccountName -eq 'krbtgt') { continue }
            $spn = @(Get-Liste $u 'ServicePrincipalName')
            if ($spn.Count -eq 0) { continue }
            $enc = Get-Deger $u 'msDS-SupportedEncryptionTypes'
            $rc4 = -not (Test-AesVar $enc)
            $pls = Get-Deger $u 'PasswordLastSet'
            $eskiParola = $null -eq $pls -or $pls -lt $ParolaSinir
            # RC4 bileti çok daha hızlı kırılır; eski parola da büyük ihtimalle zayıf ve hiç değişmemiş demektir.
            $risk = if ($rc4 -and $eskiParola) { 'Yüksek (RC4 + eski parola)' } elseif ($rc4) { 'Orta (RC4)' } elseif ($eskiParola) { 'Orta (eski parola)' } else { 'Düşük' }
            New-KullaniciSatiri $u ([ordered]@{
                KirilmaRiski = $risk
                Sifreleme    = Get-SifrelemeTurleri $enc
                SadeceRC4    = $rc4
                EskiParola   = $eskiParola
                SPN          = $spn -join '; '
            })
        }
        $liste = @($liste | Sort-Object KirilmaRiski, ParolaYasiGun -Descending)
        $seviye = 'YUKSEK'
        if (@($liste | Where-Object { $_.Ayricalikli -or $_.KirilmaRiski -like 'Yüksek*' }).Count -gt 0) { $seviye = 'KRITIK' }
        Add-Bulgu -Kod 'K01' -Baslik 'Kerberoasting' -Seviye $seviye -Nesneler $liste `
            -Aciklama "SPN tanımlı kullanıcı hesaplarının servis biletleri herhangi bir etki alanı kullanıcısı tarafından istenip çevrimdışı kırılabilir. Sadece RC4 kullanan ve parolası $ParolaYasGun günden eski hesaplar (KirilmaRiski = Yüksek) ilk hedeftir; ayrıcalıklı ya da böyle bir hesap varsa seviye KRİTİK." `
            -Oneri 'Mümkünse gMSA kullan. Kalanlarda 25+ karakter rastgele parola ver, AES zorunlu kıl (msDS-SupportedEncryptionTypes=24), gereksiz SPN''leri kaldır. Ayrıcalıklı hesaplarda SPN olmamalı.'
    }

    Invoke-Kontrol 'K02' 'AS-REP roasting' {
        $liste = @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'DoesNotRequirePreAuth' } | ForEach-Object { New-KullaniciSatiri $_ })
        $seviye = 'YUKSEK'
        if (@($liste | Where-Object { $_.Ayricalikli }).Count -gt 0) { $seviye = 'KRITIK' }
        Add-Bulgu -Kod 'K02' -Baslik 'AS-REP roasting' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Kerberos ön doğrulaması kapalı hesaplar için kimlik doğrulamadan AS-REP alınıp parola çevrimdışı kırılabilir.' `
            -Oneri '"Do not require Kerberos preauthentication" seçeneğini kaldır. Gerçekten gerekiyorsa parolayı çok uzun ve rastgele yap.'
    }

    Invoke-Kontrol 'K03' 'Ayricalikli gruplarda devre disi hesaplar' {
        $liste = @($AyricalikliKullanicilar | Where-Object { -not $_.Enabled } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K03' -Baslik 'Ayricalikli gruplarda devre disi hesaplar' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama 'Devre dışı hesaplar yeniden etkinleştirilirse yetkileri hemen geri gelir.' `
            -Oneri 'Devre dışı hesapları ayrıcalıklı gruplardan çıkar.'
    }

    Invoke-Kontrol 'K04' 'Devre disi kullanici hesaplari' {
        $liste = @($Kullanicilar | Where-Object { -not $_.Enabled -and $_.SamAccountName -notin 'krbtgt', 'Guest' -and -not $_.SID.Value.EndsWith('-501') -and -not $_.SID.Value.EndsWith('-502') } |
            ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K04' -Baslik 'Devre disi kullanici hesaplari' -Seviye 'BILGI' -Nesneler $liste `
            -Aciklama 'Devre dışı hesapların listesi. Tek başına risk değil, ama uzun süredir duranlar temizlenmeli.' `
            -Oneri 'Saklama süresini aşan hesapları sil ya da ayrı bir OU''da tut.'
    }

    Invoke-Kontrol 'K05' "$InaktifGun gundur giris yapmayan kullanicilar" {
        $liste = @($EtkinKullanicilar | Where-Object {
                $son = Get-Deger $_ 'LastLogonDate'
                $null -ne $son -and $son -lt $InaktifSinir
            } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K05' -Baslik "$InaktifGun gundur giris yapmayan kullanicilar" -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama 'Kullanılmayan ama etkin hesaplar fark edilmeden ele geçirilebilir.' `
            -Oneri 'Sahibiyle kontrol edip devre dışı bırak. Servis hesabıysa gMSA''ya taşımayı düşün.'
    }

    Invoke-Kontrol 'K06' 'Hic giris yapmamis kullanicilar' {
        $liste = @($EtkinKullanicilar | Where-Object {
                $null -eq (Get-Deger $_ 'LastLogonDate') -and (Get-Deger $_ 'whenCreated') -lt $InaktifSinir
            } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K06' -Baslik 'Hic giris yapmamis kullanicilar' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama "$InaktifGun günden eski olup hiç giriş yapmamış etkin hesaplar. Genelde açılıp unutulmuş hesaplardır; ilk parolaları da çoğu zaman tahmin edilebilir." `
            -Oneri 'Gerçekten gerekmiyorsa devre dışı bırak.'
    }

    Invoke-Kontrol 'K07' "$InaktifGun gundur gorulmeyen bilgisayarlar" {
        $liste = @($Bilgisayarlar | Where-Object {
                if (-not $_.Enabled) { return $false }
                $son = Get-Deger $_ 'LastLogonDate'
                if ($null -eq $son) { return (Get-Deger $_ 'whenCreated') -lt $InaktifSinir }
                return $son -lt $InaktifSinir
            } | ForEach-Object { New-BilgisayarSatiri $_ })
        Add-Bulgu -Kod 'K07' -Baslik "$InaktifGun gundur gorulmeyen bilgisayarlar" -Seviye 'DUSUK' -Nesneler $liste `
            -Aciklama 'Ağda olmayan bilgisayar hesapları envanteri kirletir ve kötüye kullanılabilir.' `
            -Oneri 'Devre dışı bırakıp bir süre bekledikten sonra sil.'
    }

    Invoke-Kontrol 'K08' 'Parolasi suresiz hesaplar' {
        $liste = @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'PasswordNeverExpires' } | ForEach-Object { New-KullaniciSatiri $_ })
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.Ayricalikli }).Count -gt 0) { $seviye = 'YUKSEK' }
        Add-Bulgu -Kod 'K08' -Baslik 'Parolasi suresiz hesaplar' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Parolası hiç dolmayan hesaplarda sızmış bir parola süresiz geçerli kalır.' `
            -Oneri 'Servis hesaplarını gMSA''ya taşı; kullanıcı hesaplarında bu seçeneği kaldır.'
    }

    Invoke-Kontrol 'K09' 'Parola gerektirmeyen hesaplar' {
        $liste = @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'PasswordNotRequired' } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K09' -Baslik 'Parola gerektirmeyen hesaplar' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'PASSWD_NOTREQD bayrağı olan hesaplara parola politikasına uymayan, hatta boş parola atanabilir.' `
            -Oneri 'Set-ADUser <hesap> -PasswordNotRequired $false ile bayrağı kaldır, ardından parolayı değiştir.'
    }

    Invoke-Kontrol 'K10' 'Tersinir sifreleme' {
        $liste = @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'AllowReversiblePasswordEncryption' } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K10' -Baslik 'Tersinir sifreleme' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'Bu hesapların parolası AD''de geri çözülebilir biçimde saklanır.' `
            -Oneri 'Seçeneği kaldır ve parolayı değiştir (değişiklik ancak yeni parolayla geçerli olur).'
    }

    Invoke-Kontrol 'K11' "Parolasi $ParolaYasGun gundur degismeyen hesaplar" {
        $liste = @($EtkinKullanicilar | Where-Object {
                $pls = Get-Deger $_ 'PasswordLastSet'
                $null -eq $pls -or $pls -lt $ParolaSinir
            } | ForEach-Object { New-KullaniciSatiri $_ })
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.Ayricalikli }).Count -gt 0) { $seviye = 'YUKSEK' }
        Add-Bulgu -Kod 'K11' -Baslik "Parolasi $ParolaYasGun gundur degismeyen hesaplar" -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Eski parolalar sızıntı listelerinde bulunma ve eski, zayıf hash''lerle saklanma ihtimali yüksek parolalardır.' `
            -Oneri 'Ayrıcalıklı ve servis hesaplarından başlayarak parolaları yenile.'
    }

    Invoke-Kontrol 'K12' 'krbtgt parola yasi' {
        $krbtgt = @($Kullanicilar | Where-Object { $_.SID.Value -eq "$DomSid-502" })
        $liste = @($krbtgt | Where-Object {
                $pls = Get-Deger $_ 'PasswordLastSet'
                $null -eq $pls -or $pls -lt $Simdi.AddDays(-$KrbtgtYasGun)
            } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K12' -Baslik 'krbtgt parola yasi' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama "krbtgt parolası $KrbtgtYasGun günden eski. Bu parola ele geçirilmişse (golden ticket) değişene kadar geçerli kalır." `
            -Oneri 'krbtgt parolasını iki kez, aralarında en az replikasyon süresi + en uzun bilet ömrü (genelde 10+ saat) bırakarak sıfırla.'
    }

    Invoke-Kontrol 'K13' 'Ayricalikli grup uyeleri' {
        $liste = foreach ($grupAdi in $GrupUyeleri.Keys) {
            foreach ($u in $GrupUyeleri[$grupAdi]) {
                $k = $Kullanicilar | Where-Object { $_.DistinguishedName -eq $u.DistinguishedName } | Select-Object -First 1
                [pscustomobject]@{
                    Grup           = $grupAdi
                    SamAccountName = Get-Deger $u 'sAMAccountName'
                    Tur            = ($u.ObjectClass)
                    Etkin          = if ($k) { $k.Enabled } else { '' }
                    SonGiris       = if ($k) { Format-Tarih (Get-Deger $k 'LastLogonDate') } else { '' }
                    ParolaYasiGun  = if ($k) { Get-GunFarki (Get-Deger $k 'PasswordLastSet') } else { '' }
                    DN             = $u.DistinguishedName
                }
            }
        }
        Add-Bulgu -Kod 'K13' -Baslik 'Ayricalikli grup uyeleri' -Seviye 'BILGI' -Nesneler @($liste) `
            -Aciklama 'İç içe gruplar açılarak bulunan tüm ayrıcalıklı üyeler. Her satırın bir sahibi ve gerekçesi olmalı.' `
            -Oneri 'Domain Admins''i olabildiğince küçük tut; günlük işler için ayrı, yetkisiz hesap kullan.'
    }

    Invoke-Kontrol 'K14' 'Bos olmasi gereken operator gruplari' {
        $liste = foreach ($grupAdi in 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators') {
            if (-not $GrupUyeleri.Contains($grupAdi)) { continue }
            foreach ($u in $GrupUyeleri[$grupAdi]) {
                [pscustomobject]@{ Grup = $grupAdi; SamAccountName = Get-Deger $u 'sAMAccountName'; Tur = $u.ObjectClass; DN = $u.DistinguishedName }
            }
        }
        Add-Bulgu -Kod 'K14' -Baslik 'Bos olmasi gereken operator gruplari' -Seviye 'ORTA' -Nesneler @($liste) `
            -Aciklama 'Bu yerleşik gruplar DC''lerde oturum açma, servis/sürücü yükleme ya da yedekten dosya okuma gibi Domain Admin''e giden yetkiler verir.' `
            -Oneri 'Grupları boşalt; gereken işleri özel devredilmiş yetkilerle ver.'
    }

    Invoke-Kontrol 'K15' 'Korumasiz ayricalikli hesaplar' {
        $pu = $null
        try { $pu = Get-ADGroup @AdParam -Identity "$DomSid-525" } catch { }
        $puUyeleri = @{}
        if ($pu) {
            $filtre = '(memberOf:1.2.840.113556.1.4.1941:={0})' -f (ConvertTo-LdapDegeri $pu.DistinguishedName)
            foreach ($m in @(Get-ADObject @AdParam -LDAPFilter $filtre)) { $puUyeleri[$m.DistinguishedName] = $true }
        }
        $liste = @($AyricalikliKullanicilar | Where-Object { $_.Enabled } | ForEach-Object {
                $korumali = $puUyeleri.ContainsKey($_.DistinguishedName)
                $devredilemez = [bool](Get-Deger $_ 'AccountNotDelegated')
                if (-not $korumali -and -not $devredilemez) {
                    New-KullaniciSatiri $_ ([ordered]@{ ProtectedUsers = $korumali; DevredilemezIsaretli = $devredilemez })
                }
            })
        $aciklama = 'Protected Users üyesi olmayan ve "Account is sensitive and cannot be delegated" işaretli olmayan ayrıcalıklı hesaplar. Bu hesapların kimlik bilgileri yetki devri ve NTLM/RC4 ile kötüye kullanılabilir.'
        if (-not $pu) { $aciklama += ' (Protected Users grubu bulunamadı; etki alanı 2012 R2 öncesi düzeyde olabilir.)' }
        Add-Bulgu -Kod 'K15' -Baslik 'Korumasiz ayricalikli hesaplar' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama $aciklama `
            -Oneri 'İnsan yöneticileri Protected Users''a ekle (önce bir hesapla dene). Servis hesaplarında en azından "cannot be delegated" işaretle.'
    }

    Invoke-Kontrol 'K16' 'adminCount kalintisi' {
        $liste = @($Kullanicilar | Where-Object {
                (Get-Deger $_ 'adminCount') -eq 1 -and -not $Ayricaliklilar.ContainsKey($_.DistinguishedName) -and -not $_.SID.Value.EndsWith('-502')
            } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K16' -Baslik 'adminCount kalintisi' -Seviye 'DUSUK' -Nesneler $liste `
            -Aciklama 'Bir zamanlar ayrıcalıklı grupta olmuş hesaplar. adminCount=1 kaldığı için izin devralmaları kapalı kalır ve OU''daki yetki devirleri bunlara işlemez.' `
            -Oneri 'adminCount''u temizle ve nesnede izin devralmayı yeniden aç.'
    }

    Invoke-Kontrol 'K17' 'Kisitlamasiz yetki devri' {
        $dcDN = @{}
        foreach ($dc in $DCler) { $dcDN[$dc.DistinguishedName] = $true }
        $liste = @()
        $liste += @($Bilgisayarlar | Where-Object { $_.Enabled -and (Get-Deger $_ 'TrustedForDelegation') -and -not $dcDN.ContainsKey($_.DistinguishedName) } |
            ForEach-Object { New-BilgisayarSatiri $_ ([ordered]@{ NesneTuru = 'Bilgisayar' }) })
        $liste += @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'TrustedForDelegation' } |
            ForEach-Object { New-KullaniciSatiri $_ ([ordered]@{ NesneTuru = 'Kullanici' }) })
        Add-Bulgu -Kod 'K17' -Baslik 'Kisitlamasiz yetki devri' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'DC dışındaki bu nesnelere bağlanan herkesin TGT''si bellekte kalır; sunucuyu ele geçiren, örneğin bir DC''yi zorla bağlatıp etki alanını ele geçirebilir.' `
            -Oneri 'Kısıtlı (constrained) ya da kaynak tabanlı yetki devrine geç.'
    }

    Invoke-Kontrol 'K18' 'Protokol gecisli kisitli yetki devri' {
        $liste = @()
        $liste += @($Bilgisayarlar | Where-Object { $_.Enabled -and (Get-Deger $_ 'TrustedToAuthForDelegation') } |
            ForEach-Object { New-BilgisayarSatiri $_ ([ordered]@{ NesneTuru = 'Bilgisayar'; Hedefler = (@(Get-Liste $_ 'msDS-AllowedToDelegateTo') -join '; ') }) })
        $liste += @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'TrustedToAuthForDelegation' } |
            ForEach-Object { New-KullaniciSatiri $_ ([ordered]@{ NesneTuru = 'Kullanici'; Hedefler = (@(Get-Liste $_ 'msDS-AllowedToDelegateTo') -join '; ') }) })
        Add-Bulgu -Kod 'K18' -Baslik 'Protokol gecisli kisitli yetki devri' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama '"Use any authentication protocol" açık nesneler, hedef servislere herhangi bir kullanıcı adına parola olmadan bilet alabilir.' `
            -Oneri 'Hedef listesini gözden geçir; gerekmiyorsa "Kerberos only" seçeneğine çevir.'
    }

    Invoke-Kontrol 'K19' 'Kaynak tabanli kisitli yetki devri (RBCD)' {
        $liste = @()
        foreach ($n in @($Bilgisayarlar) + @($Kullanicilar)) {
            $sd = Get-Deger $n 'msDS-AllowedToActOnBehalfOfOtherIdentity'
            if ($null -eq $sd) { continue }
            $kimler = @()
            try { $kimler = @($sd.Access | ForEach-Object { "$($_.IdentityReference)" }) } catch { $kimler = @('(okunamadı)') }
            $liste += [pscustomobject]@{
                Ad          = $n.Name
                NesneTuru   = if ($n.ObjectClass -eq 'computer') { 'Bilgisayar' } else { 'Kullanici' }
                YetkiAlanlar = $kimler -join '; '
                DN          = $n.DistinguishedName
            }
        }
        Add-Bulgu -Kod 'K19' -Baslik 'Kaynak tabanli kisitli yetki devri (RBCD)' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama 'Listelenen hesaplar bu nesneye herhangi bir kullanıcı adına erişebilir. Bilinmeyen bir kayıt saldırı izi olabilir.' `
            -Oneri 'Her kaydın gerekçesini doğrula; bilinmeyenleri kaldır ve nesneye kimin yazma yetkisi olduğuna bak.'
    }

    Invoke-Kontrol 'K20' 'SIDHistory dolu hesaplar' {
        $liste = @()
        $liste += @($Kullanicilar | Where-Object { @(Get-Liste $_ 'SIDHistory').Count -gt 0 } |
            ForEach-Object { New-KullaniciSatiri $_ ([ordered]@{ SIDHistory = (@(Get-Liste $_ 'SIDHistory') -join '; ') }) })
        $liste += @($Bilgisayarlar | Where-Object { @(Get-Liste $_ 'SIDHistory').Count -gt 0 } |
            ForEach-Object { New-BilgisayarSatiri $_ ([ordered]@{ SIDHistory = (@(Get-Liste $_ 'SIDHistory') -join '; ') }) })
        $seviye = 'ORTA'
        if (@($liste | Where-Object { "$($_.SIDHistory)" -match "$([regex]::Escape($DomSid))-5\d\d(;|$)" }).Count -gt 0) { $seviye = 'KRITIK' }
        Add-Bulgu -Kod 'K20' -Baslik 'SIDHistory dolu hesaplar' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Göç sonrası kalan SIDHistory değerleri eski yetkileri taşır. Aynı etki alanının ayrıcalıklı bir SID''i varsa bu bir saldırı izidir.' `
            -Oneri 'Göç bittiyse SIDHistory''yi temizle.'
    }

    Invoke-Kontrol 'K21' 'Sadece DES kullanan hesaplar' {
        $liste = @($EtkinKullanicilar | Where-Object { Get-Deger $_ 'UseDESKeyOnly' } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K21' -Baslik 'Sadece DES kullanan hesaplar' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'DES çok zayıftır ve güncel Windows sürümlerinde zaten kapalıdır.' `
            -Oneri '"Use only Kerberos DES encryption types" seçeneğini kaldır ve parolayı değiştir.'
    }

    Invoke-Kontrol 'K22' 'Yerlesik Administrator hesabi' {
        $admin = @($Kullanicilar | Where-Object { $_.SID.Value -eq "$DomSid-500" })
        $liste = @($admin | Where-Object {
                $pls = Get-Deger $_ 'PasswordLastSet'
                $son = Get-Deger $_ 'LastLogonDate'
                $_.Enabled -and (($null -eq $pls -or $pls -lt $ParolaSinir) -or ($null -ne $son -and $son -gt $Simdi.AddDays(-30)))
            } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K22' -Baslik 'Yerlesik Administrator hesabi' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama "RID 500 hesabı etkin ve ya parolası $ParolaYasGun günden eski ya da son 30 günde kullanılmış. Bu hesap kilitlenmez ve her saldırganın ilk hedefidir." `
            -Oneri 'Günlük işlerde kullanma; uzun rastgele parola ver ve kasada sakla.'
    }

    Invoke-Kontrol 'K23' 'Guest hesabi etkin' {
        $liste = @($Kullanicilar | Where-Object { $_.SID.Value -eq "$DomSid-501" -and $_.Enabled } | ForEach-Object { New-KullaniciSatiri $_ })
        Add-Bulgu -Kod 'K23' -Baslik 'Guest hesabi etkin' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'Etkin Guest hesabı kimliği olmayanlara etki alanı kaynaklarına erişim açabilir.' `
            -Oneri 'Guest hesabını devre dışı bırak.'
    }

    Invoke-Kontrol 'K24' 'MachineAccountQuota' {
        $maq = Get-Deger (Get-ADObject @AdParam -Identity $Domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota') 'ms-DS-MachineAccountQuota'
        $maqDeger = if ($null -eq $maq) { 10 } else { [int]$maq }
        $liste = @()
        $aciklama = 'Sıfırdan büyükse ve "Add workstations to domain" hakkı düşük yetkililerde duruyorsa herhangi bir kullanıcı etki alanına bilgisayar hesabı ekleyebilir; bu da RBCD gibi saldırılarda kullanılır.'
        if ($maqDeger -gt 0) {
            $hak = Get-BilgisayarEklemeHakki
            if ($hak.Hata) {
                $liste += [pscustomobject]@{ Ayar = 'ms-DS-MachineAccountQuota'; Deger = $maqDeger; Beklenen = 0; SeMachineAccountPrivilege = "Okunamadı: $($hak.Hata)"; Kaynak = '' }
                $aciklama += ' SeMachineAccountPrivilege SYSVOL''dan okunamadığı için kota etkin kabul edildi.'
            }
            else {
                $dusuk = @($hak.Sidler | Where-Object { $DusukYetkililer.ContainsKey($_) })
                $kimler = (@($hak.Sidler | ForEach-Object { Get-SidAdi $_ }) -join ', ')
                if ($null -eq $hak.Sidler) { $kimler = 'Hiçbir GPO''da tanımlı değil (Windows varsayılanı: Authenticated Users)'; $dusuk = @('S-1-5-11') }
                if ($dusuk.Count -gt 0) {
                    $liste += [pscustomobject]@{ Ayar = 'ms-DS-MachineAccountQuota'; Deger = $maqDeger; Beklenen = 0; SeMachineAccountPrivilege = $kimler; Kaynak = $hak.Kaynak }
                }
                else {
                    $aciklama += " Kota $maqDeger, ama hak düşük yetkililerden alınmış ($kimler; kaynak: $($hak.Kaynak)); bu yüzden bulgu sayılmadı."
                }
            }
        }
        Add-Bulgu -Kod 'K24' -Baslik 'MachineAccountQuota' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama $aciklama `
            -Oneri 'Kotayı 0 yap ya da DC''lere uygulanan GPO''da "Add workstations to domain" hakkını sadece bilgisayar ekleyecek gruba ver.'
    }

    Invoke-Kontrol 'K25' 'Varsayilan parola politikasi' {
        $pp = Get-ADDefaultDomainPasswordPolicy @AdParam
        $liste = @()
        if ($pp.MinPasswordLength -lt 12) { $liste += [pscustomobject]@{ Ayar = 'MinPasswordLength'; Deger = $pp.MinPasswordLength; Beklenen = '12+ (tercihen 14+)' } }
        if (-not $pp.ComplexityEnabled) { $liste += [pscustomobject]@{ Ayar = 'ComplexityEnabled'; Deger = $pp.ComplexityEnabled; Beklenen = 'True' } }
        if ($pp.LockoutThreshold -eq 0) { $liste += [pscustomobject]@{ Ayar = 'LockoutThreshold'; Deger = 0; Beklenen = '5-10 arası' } }
        if ($pp.ReversibleEncryptionEnabled) { $liste += [pscustomobject]@{ Ayar = 'ReversibleEncryptionEnabled'; Deger = $true; Beklenen = 'False' } }
        if ($pp.PasswordHistoryCount -lt 12) { $liste += [pscustomobject]@{ Ayar = 'PasswordHistoryCount'; Deger = $pp.PasswordHistoryCount; Beklenen = '12+' } }
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.Ayar -in 'LockoutThreshold', 'ReversibleEncryptionEnabled' }).Count -gt 0) { $seviye = 'YUKSEK' }
        $fgpp = @()
        try { $fgpp = @(Get-ADFineGrainedPasswordPolicy @AdParam -Filter *) } catch { }
        $aciklama = 'Etki alanı varsayılan parola politikasının zayıf ayarları.'
        if ($fgpp.Count -gt 0) { $aciklama += " Ayrıca $($fgpp.Count) adet ayrıntılı parola politikası (FGPP) var; bunların uygulandığı hesaplarda bu ayarlar geçerli değildir, bkz. K54." }
        Add-Bulgu -Kod 'K25' -Baslik 'Varsayilan parola politikasi' -Seviye $seviye -Nesneler $liste `
            -Aciklama $aciklama `
            -Oneri 'En az 12-14 karakter, hesap kilitleme açık, tersinir şifreleme kapalı. Uzun parola, sık değişimden daha etkilidir.'
    }

    Invoke-Kontrol 'K26' 'LAPS kapsami' {
        $liste = @()
        $seviye = 'ORTA'
        if (-not $LapsEski -and -not $LapsYeni) {
            $seviye = 'YUKSEK'
            $liste += [pscustomobject]@{ Durum = 'LAPS şeması yok'; Aciklama = 'Ne eski LAPS ne Windows LAPS öznitelikleri şemada bulundu.' }
        }
        else {
            $dcDN = @{}
            foreach ($dc in $DCler) { $dcDN[$dc.DistinguishedName] = $true }
            $liste += @($Bilgisayarlar | Where-Object { $_.Enabled -and -not $dcDN.ContainsKey($_.DistinguishedName) } | Where-Object {
                    $var = $false
                    if ($LapsEski -and $null -ne (Get-Deger $_ 'ms-Mcs-AdmPwdExpirationTime')) { $var = $true }
                    if ($LapsYeni -and $null -ne (Get-Deger $_ 'msLAPS-PasswordExpirationTime')) { $var = $true }
                    -not $var
                } | ForEach-Object { New-BilgisayarSatiri $_ })
        }
        Add-Bulgu -Kod 'K26' -Baslik 'LAPS kapsami' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'LAPS parolası olmayan bilgisayarlarda yerel yönetici parolası büyük ihtimalle her yerde aynıdır; bir makineden diğerine geçmeyi kolaylaştırır.' `
            -Oneri 'Windows LAPS''ı GPO/Intune ile tüm üye sunucu ve istemcilere yay.'
    }

    # Son giriş eşiğine göre "aktif" sütunu ekler; seviye sadece aktif makinelere göre belirlenir.
    function Get-IsletimSistemiListesi {
        param([string]$Desen)
        @($Bilgisayarlar | Where-Object { $_.Enabled -and "$(Get-Deger $_ 'OperatingSystem')" -match $Desen } | ForEach-Object {
                $son = Get-Deger $_ 'LastLogonDate'
                New-BilgisayarSatiri $_ ([ordered]@{ Aktif = ($null -ne $son -and $son -ge $InaktifSinir) })
            } | Sort-Object Aktif, IsletimSistemi -Descending)
    }

    Invoke-Kontrol 'K27' 'Destegi bitmis eski isletim sistemleri' {
        $liste = Get-IsletimSistemiListesi 'Windows (XP|Vista|7|8|8\.1)\b|Windows Server (2000|2003|2008|2012)\b|Windows NT|Windows 2000'
        $aktif = @($liste | Where-Object { $_.Aktif }).Count
        $seviye = if ($aktif -gt 0) { 'YUKSEK' } else { 'DUSUK' }
        Add-Bulgu -Kod 'K27' -Baslik 'Destegi bitmis eski isletim sistemleri' -Seviye $seviye -Nesneler $liste `
            -Aciklama "Uzun zamandır güvenlik güncellemesi almayan sistemler (Windows 7/8.1, Server 2003-2012 R2 vb.). $($liste.Count) makineden $aktif tanesi son $InaktifGun günde görülmüş (Aktif = True); diğerleri büyük ihtimalle artık yok." `
            -Oneri 'Aktif olanları yükselt ya da ağdan yalıt; aktif olmayanları K07 ile birlikte devre dışı bırakıp temizle.'
    }

    Invoke-Kontrol 'K53' 'Windows 10' {
        $liste = Get-IsletimSistemiListesi 'Windows 10\b'
        $aktif = @($liste | Where-Object { $_.Aktif }).Count
        $seviye = if ($aktif -gt 0) { 'ORTA' } else { 'DUSUK' }
        Add-Bulgu -Kod 'K53' -Baslik 'Windows 10' -Seviye $seviye -Nesneler $liste `
            -Aciklama "Windows 10'un genel desteği Ekim 2025'te bitti; LTSC sürümleri ya da ücretli ESU kapsamındaki makineler hâlâ güncelleme alır. $($liste.Count) makineden $aktif tanesi son $InaktifGun günde görülmüş." `
            -Oneri 'ESU kapsamını doğrula ve Windows 11 geçişini planla; aktif olmayan hesapları temizle.'
    }

    Invoke-Kontrol 'K54' 'Zayif ayrintili parola politikalari (FGPP)' {
        $politikalar = @(Get-ADFineGrainedPasswordPolicy @AdParam -Filter * -Properties AppliesTo)
        $liste = @(foreach ($pso in $politikalar) {
                $zayif = @()
                if ($pso.MinPasswordLength -lt 12) { $zayif += "MinPasswordLength=$($pso.MinPasswordLength)" }
                if (-not $pso.ComplexityEnabled) { $zayif += 'Karmaşıklık kapalı' }
                if ($pso.LockoutThreshold -eq 0) { $zayif += 'Hesap kilitleme kapalı' }
                if ($pso.ReversibleEncryptionEnabled) { $zayif += 'Tersinir şifreleme açık' }
                if ($pso.PasswordHistoryCount -lt 12) { $zayif += "PasswordHistoryCount=$($pso.PasswordHistoryCount)" }
                if ($zayif.Count -eq 0) { continue }

                # Uygulanan grupların kullanıcıları iç içe açılarak sayılır (öncelik sırası hesaba katılmaz).
                $hedefAdlari = @()
                $kullaniciDN = @{}
                $ayricalikliEtkilenen = @()
                foreach ($dn in @($pso.AppliesTo)) {
                    $n = Get-ADObject @AdParam -Identity $dn -Properties sAMAccountName
                    $hedefAdlari += Get-Deger $n 'sAMAccountName'
                    if ($n.ObjectClass -eq 'group') {
                        $filtre = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f (ConvertTo-LdapDegeri $dn)
                        foreach ($u in @(Get-ADObject @AdParam -LDAPFilter $filtre)) { $kullaniciDN[$u.DistinguishedName] = $true }
                    }
                    else { $kullaniciDN[$dn] = $true }
                }
                foreach ($dn in $kullaniciDN.Keys) { if ($Ayricaliklilar.ContainsKey($dn)) { $ayricalikliEtkilenen += ($dn -split ',')[0] -replace '^CN=' } }

                [pscustomobject]@{
                    Politika            = $pso.Name
                    Oncelik             = $pso.Precedence
                    Zayifliklar         = $zayif -join ', '
                    MinUzunluk          = $pso.MinPasswordLength
                    KilitlemeEsigi      = $pso.LockoutThreshold
                    MaxParolaYasi       = "$($pso.MaxPasswordAge)"
                    UygulananHedefler   = $hedefAdlari -join ', '
                    EtkilenenKullanici  = $kullaniciDN.Count
                    AyricalikliEtkilenen = $ayricalikliEtkilenen -join ', '
                }
            })
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.Zayifliklar -match 'kilitleme kapalı|Tersinir' -and $_.EtkilenenKullanici -gt 0 }).Count -gt 0) { $seviye = 'YUKSEK' }
        if (@($liste | Where-Object { $_.AyricalikliEtkilenen }).Count -gt 0) { $seviye = 'YUKSEK' }
        Add-Bulgu -Kod 'K54' -Baslik 'Zayif ayrintili parola politikalari (FGPP)' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'FGPP''ler uygulandıkları hesaplarda varsayılan politikanın yerine geçer. Zayıf bir FGPP (örneğin hesap kilitleme kapalı) o hesapları parola denemesine açık bırakır. Etkilenen kullanıcı sayısı iç içe gruplar açılarak hesaplanır; aynı kullanıcıya birden çok FGPP uygulanıyorsa önceliği düşük olan geçerli değildir.' `
            -Oneri 'Zayıflıkları gider ya da FGPP''nin kapsamını gerçekten ihtiyacı olan hesaplara indir. Kilitleme istenmeyen servis hesapları için uzun rastgele parola ya da gMSA kullan.'
    }

    Invoke-Kontrol 'K55' 'Ayricalikli gruplarda insan olmayan hesaplar' {
        $kullaniciByDN = @{}
        foreach ($u in $Kullanicilar) { $kullaniciByDN[$u.DistinguishedName] = $u }
        $servisDeseni = '(^|[_.-])(svc|srv|sql|app)([_.-]|\d|$)|service'
        $liste = @(foreach ($grupAdi in $GrupUyeleri.Keys) {
                foreach ($m in $GrupUyeleri[$grupAdi]) {
                    $sinif = "$($m.ObjectClass)"
                    $sam = "$(Get-Deger $m 'sAMAccountName')"
                    $tur = $null
                    if ($sinif -eq 'computer') { $tur = 'Bilgisayar' }
                    elseif ($sinif -eq 'msDS-GroupManagedServiceAccount') { $tur = 'gMSA' }
                    elseif ($sinif -eq 'msDS-ManagedServiceAccount') { $tur = 'sMSA' }
                    elseif ($kullaniciByDN.ContainsKey($m.DistinguishedName)) {
                        $u = $kullaniciByDN[$m.DistinguishedName]
                        $nedenler = @()
                        if (@(Get-Liste $u 'ServicePrincipalName').Count -gt 0) { $nedenler += 'SPN' }
                        if (Get-Deger $u 'PasswordNeverExpires') { $nedenler += 'süresiz parola' }
                        if ($sam -match $servisDeseni) { $nedenler += 'ad' }
                        # Tek başına "süresiz parola" insan yöneticide de olabilir; en az bir güçlü işaret gerekli.
                        if ($nedenler -contains 'SPN' -or $nedenler -contains 'ad') { $tur = "Servis hesabı ($($nedenler -join ', '))" }
                    }
                    if (-not $tur) { continue }
                    $not = ''
                    if ($grupAdi -in 'Key Admins', 'Enterprise Key Admins' -and $tur -eq 'gMSA') { $not = 'ADFS / Windows Hello key trust için beklenebilir' }
                    [pscustomobject]@{ Grup = $grupAdi; Hesap = $sam; Tur = $tur; Not = $not; DN = $m.DistinguishedName }
                }
            })
        $seviye = 'ORTA'
        if (@($liste | Where-Object { -not $_.Not -and $_.Grup -in 'Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins', 'Domain Admins (birincil grup)' }).Count -gt 0) { $seviye = 'YUKSEK' }
        Add-Bulgu -Kod 'K55' -Baslik 'Ayricalikli gruplarda insan olmayan hesaplar' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Ayrıcalıklı gruplardaki gMSA, bilgisayar ve servis hesapları. Bu hesapların çalıştığı sunucuyu ele geçiren, hesabın yetkisini de alır; bu sunucular fiilen Tier 0 olur. Servis hesapları ad, SPN ve süresiz parola işaretlerinden tahmin edilir.' `
            -Oneri 'Servise sadece gereken yetkiyi devret (örneğin belirli OU''larda), Domain Admins / Administrators üyeliğini kaldır. Kalması zorunluysa çalıştığı sunucuyu Tier 0 olarak koru.'
    }

    Invoke-Kontrol 'K28' 'Pre-Windows 2000 Compatible Access' {
        $grup = Get-ADGroup @AdParam -Identity 'S-1-5-32-554' -Properties member
        $tehlikeli = @{ 'S-1-5-11' = 'Authenticated Users'; 'S-1-1-0' = 'Everyone'; 'S-1-5-7' = 'Anonymous Logon' }
        $liste = foreach ($m in @($grup.member)) {
            foreach ($sid in $tehlikeli.Keys) {
                if ($m -like "CN=$sid,*") { [pscustomobject]@{ Uye = $tehlikeli[$sid]; SID = $sid; DN = $m } }
            }
        }
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.SID -in 'S-1-1-0', 'S-1-5-7' }).Count -gt 0) { $seviye = 'YUKSEK' }
        Add-Bulgu -Kod 'K28' -Baslik 'Pre-Windows 2000 Compatible Access' -Seviye $seviye -Nesneler @($liste) `
            -Aciklama 'Bu grup kullanıcı ve grup nesnelerinin geniş okunmasına izin verir. Anonymous/Everyone üyeliği kimliksiz numaralandırmaya açar.' `
            -Oneri 'Anonymous Logon ve Everyone''ı çıkar. Authenticated Users''ı çıkarmadan önce eski uygulamaları test et.'
    }

    Invoke-Kontrol 'K29' 'AD Geri Donusum Kutusu' {
        $rb = @(Get-ADOptionalFeature @AdParam -Filter "Name -like 'Recycle Bin Feature'")
        $liste = @()
        if ($rb.Count -eq 0 -or @($rb[0].EnabledScopes).Count -eq 0) {
            $liste += [pscustomobject]@{ Ozellik = 'Recycle Bin Feature'; Durum = 'Kapalı' }
        }
        Add-Bulgu -Kod 'K29' -Baslik 'AD Geri Donusum Kutusu' -Seviye 'DUSUK' -Nesneler $liste `
            -Aciklama 'Kapalıysa yanlışlıkla ya da kötü niyetle silinen nesneler özellikleriyle birlikte geri getirilemez.' `
            -Oneri 'Enable-ADOptionalFeature ile aç (geri alınamaz, orman düzeyi 2008 R2+ gerekir).'
    }

    Invoke-Kontrol 'K30' 'Guven iliskileri' {
        $guvenler = @(Get-ADTrust @AdParam -Filter *)
        $liste = foreach ($t in $guvenler) {
            $ic = [bool](Get-Deger $t 'IntraForest')
            $sidFiltre = [bool](Get-Deger $t 'SIDFilteringQuarantined')
            $orman = [bool](Get-Deger $t 'ForestTransitive')
            $sorun = ''
            if (-not $ic -and -not $orman -and -not $sidFiltre) { $sorun = 'Dış güvende SID filtreleme kapalı' }
            [pscustomobject]@{
                Ad                 = $t.Name
                Yon                = "$($t.Direction)"
                Tur                = "$($t.TrustType)"
                OrmanIci           = $ic
                OrmanGuveni        = $orman
                SIDFiltreleme      = $sidFiltre
                SeciciKimlikDogr   = [bool](Get-Deger $t 'SelectiveAuthentication')
                Sorun              = $sorun
            }
        }
        $liste = @($liste)
        $seviye = 'BILGI'
        if (@($liste | Where-Object { $_.Sorun }).Count -gt 0) { $seviye = 'ORTA' }
        Add-Bulgu -Kod 'K30' -Baslik 'Guven iliskileri' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Etki alanının tüm güven ilişkileri. Dış güvenlerde SID filtreleme kapalıysa karşı taraf SIDHistory ile yetki yükseltebilir.' `
            -Oneri 'Kullanılmayan güvenleri kaldır; dış güvenlerde SID filtrelemeyi ve mümkünse seçici kimlik doğrulamayı aç.'
    }

    # --- ACL: DCSync ve AdminSDHolder ---------------------------------------

    $InheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $GuidGetChanges = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'      # DS-Replication-Get-Changes
    $GuidGetChangesAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
    $GuidResetPassword = [guid]'00299570-246d-11d0-a768-00aa006e0529'   # User-Force-Change-Password
    $GuidChangePassword = [guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'  # User-Change-Password
    $GuidKeyCredLink = [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'     # msDS-KeyCredentialLink
    $GuidUserCert = [guid]'bf967a7f-0de6-11d0-a285-00aa003049e2'        # userCertificate
    $GuidTsLisans = [guid]'5805bc62-bdc9-4428-a5e2-856a0f4c185e'        # Terminal Server License Server özellik kümesi
    $GuidTsSunucu = [guid]'6db69a1c-9422-11d1-aebd-0000f80367c1'        # terminalServer

    $KokSid = if ($RootSid) { $RootSid } else { $DomSid }
    # Bu SID'lerin etki alanı kökünde ve AdminSDHolder'da geniş yetkisi olması normaldir.
    $BeklenenYoneticiler = @{
        'S-1-5-18'     = 'SYSTEM'
        'S-1-5-32-544' = 'Administrators'
        "$DomSid-512"  = 'Domain Admins'
        "$KokSid-519"  = 'Enterprise Admins'
    }
    # Çoğaltma hakları için ayrıca DC grupları da beklenir.
    $BeklenenCogaltma = $BeklenenYoneticiler.Clone()
    $BeklenenCogaltma['S-1-5-9'] = 'Enterprise Domain Controllers'
    $BeklenenCogaltma["$DomSid-516"] = 'Domain Controllers'
    $BeklenenCogaltma["$DomSid-521"] = 'Read-only Domain Controllers'
    $BeklenenCogaltma["$KokSid-498"] = 'Enterprise Read-only Domain Controllers'

    # Nesnenin kendisine uygulanan Allow kayıtlarını SID bazında döndürür.
    function Get-NesneIzinleri {
        param([string]$DN)
        $n = Get-ADObject @AdParam -Identity $DN -Properties nTSecurityDescriptor
        foreach ($r in $n.nTSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ("$($r.AccessControlType)" -ne 'Allow') { continue }
            if (($r.PropagationFlags -band $InheritOnly) -eq $InheritOnly) { continue }
            [pscustomobject]@{
                Sid      = $r.IdentityReference.Value
                Hak      = [int]$r.ActiveDirectoryRights
                Tip      = $r.ObjectType
                Miras    = $r.IsInherited
            }
        }
    }

    # Yetkiyi tek tek bitlerle okunur hale getirir (bileşik maske -band hatasına düşmeden).
    function Get-YazmaHaklari {
        param($Izin)
        $h = @()
        if (($Izin.Hak -band 0xF01FF) -eq 0xF01FF) { return @('GenericAll') }
        if ($Izin.Hak -band 0x40000) { $h += 'WriteDacl' }
        if ($Izin.Hak -band 0x80000) { $h += 'WriteOwner' }
        if ($Izin.Hak -band 0x20) { $h += $(if ($Izin.Tip -eq [guid]::Empty) { 'WriteProperty (tümü)' } else { "WriteProperty ($($Izin.Tip))" }) }
        if ($Izin.Hak -band 0x8) { $h += 'Self (doğrulanmış yazma)' }
        if ($Izin.Hak -band 0x100) {
            if ($Izin.Tip -eq [guid]::Empty) { $h += 'Tüm genişletilmiş haklar' }
            elseif ($Izin.Tip -eq $GuidResetPassword) { $h += 'Parola sıfırlama' }
        }
        $h
    }

    $SyncHesabiDeseni = '^(MSOL_|Sync_|AAD_|AZUREADSSOACC)'

    Invoke-Kontrol 'K50' 'DCSync cogaltma hakki' {
        $izinler = @(Get-NesneIzinleri $Domain.DistinguishedName)
        $kisiler = @{}
        foreach ($i in $izinler) {
            if ($BeklenenCogaltma.ContainsKey($i.Sid)) { continue }
            if (-not $kisiler.ContainsKey($i.Sid)) { $kisiler[$i.Sid] = @{ Changes = $false; ChangesAll = $false } }
            $tam = ($i.Hak -band 0xF01FF) -eq 0xF01FF
            $tumGenisletilmis = ($i.Hak -band 0x100) -and $i.Tip -eq [guid]::Empty
            if ($tam -or $tumGenisletilmis -or (($i.Hak -band 0x100) -and $i.Tip -eq $GuidGetChanges)) { $kisiler[$i.Sid].Changes = $true }
            if ($tam -or $tumGenisletilmis -or (($i.Hak -band 0x100) -and $i.Tip -eq $GuidGetChangesAll)) { $kisiler[$i.Sid].ChangesAll = $true }
        }
        $liste = @(foreach ($sid in $kisiler.Keys) {
                $k = $kisiler[$sid]
                if (-not ($k.Changes -and $k.ChangesAll)) { continue }
                $ad = Get-SidAdi $sid
                $sam = ($ad -split '\\')[-1]
                [pscustomobject]@{
                    Hesap = $ad
                    SID   = $sid
                    Not   = if ($sam -match $SyncHesabiDeseni) { 'Entra Connect / eşitleme hesabı olabilir: beklenen, ama Tier 0 gibi korunmalı' } else { 'Beklenmedik' }
                }
            })
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.Not -eq 'Beklenmedik' }).Count -gt 0) { $seviye = 'KRITIK' }
        Add-Bulgu -Kod 'K50' -Baslik 'DCSync cogaltma hakki' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Etki alanı kökünde hem DS-Replication-Get-Changes hem de Get-Changes-All hakkı olan, DC ve yönetici grupları dışındaki hesaplar. Bu hesaplar DCSync ile krbtgt dahil tüm parola hash''lerini çekebilir.' `
            -Oneri 'Beklenmedik kayıtları kaldır ve ne zaman, kim tarafından eklendiğini araştır (saldırı izi olabilir). Eşitleme hesaplarının parolasını ve bulunduğu sunucuyu Tier 0 olarak koru.'
    }

    Invoke-Kontrol 'K51' 'Etki alani kokunde yazma yetkisi' {
        $liste = @(foreach ($i in @(Get-NesneIzinleri $Domain.DistinguishedName)) {
                if ($BeklenenYoneticiler.ContainsKey($i.Sid)) { continue }
                # Varsayılan: Key Admins / Enterprise Key Admins msDS-KeyCredentialLink yazar.
                if ($i.Sid -in "$DomSid-526", "$KokSid-527" -and $i.Tip -eq $GuidKeyCredLink) { continue }
                $haklar = @(Get-YazmaHaklari $i | Where-Object { $_ -notin 'Self (doğrulanmış yazma)', 'Parola sıfırlama' })
                if ($haklar.Count -eq 0) { continue }
                [pscustomobject]@{ Hesap = Get-SidAdi $i.Sid; SID = $i.Sid; Haklar = $haklar -join ', '; Miras = $i.Miras }
            })
        $seviye = 'YUKSEK'
        if (@($liste | Where-Object { $DusukYetkililer.ContainsKey($_.SID) -or $_.Haklar -match 'GenericAll|WriteDacl|WriteOwner' }).Count -gt 0) { $seviye = 'KRITIK' }
        Add-Bulgu -Kod 'K51' -Baslik 'Etki alani kokunde yazma yetkisi' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Etki alanı kök nesnesine yazabilen hesaplar. WriteDacl/WriteOwner/GenericAll olan biri kendine DCSync hakkı verebilir; gPLink gibi özniteliklere yazabilen tüm etki alanına GPO bağlayabilir.' `
            -Oneri 'Beklenmedik kayıtları kaldır. Gerekli bir devir varsa (örneğin belirli bir öznitelik) en dar haliyle ve belgelenerek ver.'
    }

    Invoke-Kontrol 'K52' 'AdminSDHolder uzerinde beklenmedik yetki' {
        $dn = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
        $liste = @(foreach ($i in @(Get-NesneIzinleri $dn)) {
                if ($BeklenenYoneticiler.ContainsKey($i.Sid)) { continue }
                if ($i.Sid -eq 'S-1-5-10') { continue }   # SELF
                # Windows'un varsayılan dar izinleri
                if ($i.Sid -in 'S-1-1-0', 'S-1-5-10' -and $i.Tip -eq $GuidChangePassword) { continue }
                if ($i.Sid -eq "$DomSid-517" -and $i.Tip -eq $GuidUserCert) { continue }
                if ($i.Sid -eq 'S-1-5-32-561' -and $i.Tip -in $GuidTsLisans, $GuidTsSunucu) { continue }
                $haklar = @(Get-YazmaHaklari $i)
                if ($haklar.Count -eq 0) { continue }
                [pscustomobject]@{ Hesap = Get-SidAdi $i.Sid; SID = $i.Sid; Haklar = $haklar -join ', '; Miras = $i.Miras }
            })
        $seviye = 'YUKSEK'
        if (@($liste | Where-Object { $DusukYetkililer.ContainsKey($_.SID) -or $_.Haklar -match 'GenericAll|WriteDacl|WriteOwner|Parola' }).Count -gt 0) { $seviye = 'KRITIK' }
        Add-Bulgu -Kod 'K52' -Baslik 'AdminSDHolder uzerinde beklenmedik yetki' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'AdminSDHolder''ın izinleri SDProp ile her 60 dakikada bir tüm korumalı hesap ve gruplara (Domain Admins üyeleri dahil) kopyalanır. Buradaki beklenmedik bir yetki, bütün ayrıcalıklı hesaplar üzerinde kalıcı bir arka kapıdır.' `
            -Oneri 'Beklenmedik kayıtları AdminSDHolder''dan kaldır; SDProp bir saat içinde korumalı nesnelere yayar. Kaydın kim tarafından eklendiğini araştır.'
    }

    # --- ADCS sertifika şablonları ------------------------------------------

    $EnrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'      # Certificate-Enrollment
    $AutoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'  # Certificate-AutoEnrollment

    $EkuAdlari = @{
        '1.3.6.1.5.5.7.3.1'      = 'Server Authentication'
        '1.3.6.1.5.5.7.3.2'      = 'Client Authentication'
        '1.3.6.1.5.2.3.4'        = 'PKINIT Client Authentication'
        '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'
        '2.5.29.37.0'            = 'Any Purpose'
        '1.3.6.1.4.1.311.20.2.1' = 'Certificate Request Agent'
        '1.3.6.1.5.5.7.3.4'      = 'Secure Email'
        '1.3.6.1.5.5.7.3.3'      = 'Code Signing'
        '1.3.6.1.4.1.311.10.3.4' = 'Encrypting File System'
    }
    $IstemciEkulari = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')

    $Sablonlar = @()
    $AdcsHata = $null
    $CaSayisi = 0
    $caListesi = @()
    try {
        $pki = "CN=Public Key Services,CN=Services,$($RootDSE.configurationNamingContext)"
        $yayin = @{}   # şablon adı -> CA adları
        $caListesi = @(Get-ADObject @AdParam -SearchBase "CN=Enrollment Services,$pki" -LDAPFilter '(objectClass=pKIEnrollmentService)' `
                -Properties certificateTemplates, dNSHostName -ErrorAction Stop)
        $CaSayisi = $caListesi.Count
        foreach ($ca in $caListesi) {
            foreach ($s in @(Get-Liste $ca 'certificateTemplates')) {
                if (-not $yayin.ContainsKey($s)) { $yayin[$s] = @() }
                $yayin[$s] += $ca.Name
            }
        }

        $sablonNesneleri = @(Get-ADObject @AdParam -SearchBase "CN=Certificate Templates,$pki" -LDAPFilter '(objectClass=pKICertificateTemplate)' `
                -Properties displayName, 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', `
                'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'msPKI-Template-Schema-Version', nTSecurityDescriptor -ErrorAction Stop)

        foreach ($sb in $sablonNesneleri) {
            $adBayrak = Get-Deger $sb 'msPKI-Certificate-Name-Flag'
            $kayitBayrak = Get-Deger $sb 'msPKI-Enrollment-Flag'
            $ra = Get-Deger $sb 'msPKI-RA-Signature'
            $sema = Get-Deger $sb 'msPKI-Template-Schema-Version'
            $adBayrak = if ($null -eq $adBayrak) { 0 } else { [int]$adBayrak }
            $kayitBayrak = if ($null -eq $kayitBayrak) { 0 } else { [int]$kayitBayrak }
            $ra = if ($null -eq $ra) { 0 } else { [int]$ra }
            $sema = if ($null -eq $sema) { 1 } else { [int]$sema }

            $ekuler = @(@(Get-Liste $sb 'pKIExtendedKeyUsage') + @(Get-Liste $sb 'msPKI-Certificate-Application-Policy') | Sort-Object -Unique)
            $ekuMetin = if ($ekuler.Count -eq 0) { 'Yok (her amaç)' } else {
                ($ekuler | ForEach-Object { if ($EkuAdlari.ContainsKey($_)) { $EkuAdlari[$_] } else { $_ } }) -join ', '
            }
            $herAmac = $ekuler.Count -eq 0 -or $ekuler -contains '2.5.29.37.0'
            $istemciDog = $herAmac -or @($ekuler | Where-Object { $IstemciEkulari -contains $_ }).Count -gt 0
            $talepAjani = $ekuler -contains '1.3.6.1.4.1.311.20.2.1'

            # Yetkiler tek tek bitlerle kontrol ediliyor. GenericAll / GenericWrite gibi bileşik
            # maskelerle -band yapmak okuma haklarını da yakalar ve yanlış alarm üretir.
            $kayitHakki = @()
            $yazmaHakki = @()
            $sd = Get-Deger $sb 'nTSecurityDescriptor'
            if ($sd) {
                foreach ($r in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ("$($r.AccessControlType)" -ne 'Allow') { continue }
                    $sid = $r.IdentityReference.Value
                    if (-not $DusukYetkililer.ContainsKey($sid)) { continue }
                    $kim = $DusukYetkililer[$sid]
                    $hak = [int]$r.ActiveDirectoryRights
                    $tip = $r.ObjectType
                    $tamYetki = ($hak -band 0xF01FF) -eq 0xF01FF

                    if ($tamYetki -or (($hak -band 0x100) -and ($tip -eq [guid]::Empty -or $tip -eq $EnrollGuid -or $tip -eq $AutoEnrollGuid))) {
                        $kayitHakki += $kim
                    }
                    $yazma = @()
                    if ($tamYetki) { $yazma += 'GenericAll' }
                    else {
                        if ($hak -band 0x40000) { $yazma += 'WriteDacl' }
                        if ($hak -band 0x80000) { $yazma += 'WriteOwner' }
                        if ($hak -band 0x20) { $yazma += $(if ($tip -eq [guid]::Empty) { 'WriteProperty (tümü)' } else { "WriteProperty ($tip)" }) }
                    }
                    if ($yazma.Count -gt 0) { $yazmaHakki += '{0}: {1}' -f $kim, ($yazma -join '+') }
                }
            }

            $cn = $sb.Name
            $Sablonlar += [pscustomobject][ordered]@{
                Sablon             = $cn
                GorunenAd          = Get-Deger $sb 'displayName'
                Yayinda            = $yayin.ContainsKey($cn)
                CA                 = if ($yayin.ContainsKey($cn)) { ($yayin[$cn] -join ', ') } else { '' }
                SemaSurumu         = $sema
                EKU                = $ekuMetin
                IstemciDogrulama   = $istemciDog
                HerAmac            = $herAmac
                TalepAjani         = $talepAjani
                KonuIstekte        = ($adBayrak -band 0x1) -ne 0
                YoneticiOnayi      = ($kayitBayrak -band 0x2) -ne 0
                YetkiliImza        = $ra
                GuvenlikUzantisiYok = ($kayitBayrak -band 0x80000) -ne 0
                Korumasiz          = (($kayitBayrak -band 0x2) -eq 0) -and $ra -eq 0
                DusukYetkiliKayit  = (@($kayitHakki | Sort-Object -Unique) -join ', ')
                DusukYetkiliYazma  = (@($yazmaHakki | Sort-Object -Unique) -join '; ')
                DN                 = $sb.DistinguishedName
            }
        }
    }
    catch {
        $AdcsHata = $_.Exception.Message
    }

    # Parametre adı Invoke-Kontrol'ün $Blok'u ile çakışmasın: PowerShell değişkenleri
    # çalışma anında çağrı zincirinden çözer, aynı ad kendini çağırmaya yol açar.
    function Invoke-AdcsKontrol {
        param([string]$Kod, [string]$Baslik, [scriptblock]$AdcsBlok)
        Invoke-Kontrol $Kod $Baslik {
            if ($AdcsHata) { throw "ADCS nesneleri okunamadı: $AdcsHata" }
            & $AdcsBlok
        }
    }

    $sablonSutunlari = 'Sablon', 'GorunenAd', 'CA', 'SemaSurumu', 'EKU', 'KonuIstekte', 'YoneticiOnayi', 'YetkiliImza', 'DusukYetkiliKayit', 'DusukYetkiliYazma', 'DN'
    $riskliKayit = @($Sablonlar | Where-Object { $_.Yayinda -and $_.DusukYetkiliKayit })

    Invoke-AdcsKontrol 'K39' 'Yayindaki sertifika sablonlari' {
        $liste = @($Sablonlar | Where-Object { $_.Yayinda } | Select-Object Sablon, GorunenAd, CA, SemaSurumu, EKU, KonuIstekte, YoneticiOnayi, YetkiliImza, GuvenlikUzantisiYok, DusukYetkiliKayit, DusukYetkiliYazma)
        $aciklama = "Ortamda $CaSayisi kurumsal CA ve $(@($Sablonlar).Count) şablon var; bunlardan $($liste.Count) tanesi en az bir CA'da yayında."
        if ($CaSayisi -eq 0) { $aciklama = 'Etki alanında kurumsal CA (ADCS) bulunamadı.' }
        Add-Bulgu -Kod 'K39' -Baslik 'Yayindaki sertifika sablonlari' -Seviye 'BILGI' -Nesneler $liste `
            -Aciklama $aciklama `
            -Oneri 'Kullanılmayan şablonları CA''lardan kaldır (Certificate Templates > Delete). Yayında olmayan şablon talep edilemez.'
    }

    Invoke-AdcsKontrol 'K40' 'ESC1 konu istekte belirtilebilen sablonlar' {
        $liste = @($riskliKayit | Where-Object { $_.KonuIstekte -and $_.IstemciDogrulama -and $_.Korumasiz } | Select-Object $sablonSutunlari)
        Add-Bulgu -Kod 'K40' -Baslik 'ESC1 konu istekte belirtilebilen sablonlar' -Seviye 'KRITIK' -Nesneler $liste `
            -Aciklama 'Düşük yetkili kullanıcılar bu şablonla istedikleri bir kullanıcı (örneğin bir Domain Admin) adına kimlik doğrulama sertifikası alabilir. Doğrudan etki alanı ele geçirme yoludur.' `
            -Oneri '"Supply in the request" seçeneğini kapat (Build from AD information), ya da CA Manager Approval iste, ya da kayıt hakkını küçük bir gruba indir.'
    }

    Invoke-AdcsKontrol 'K41' 'ESC2 her amacli veya EKU suz sablonlar' {
        $liste = @($riskliKayit | Where-Object { $_.HerAmac -and $_.Korumasiz } | Select-Object $sablonSutunlari)
        Add-Bulgu -Kod 'K41' -Baslik 'ESC2 her amacli veya EKU suz sablonlar' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'Any Purpose ya da EKU''su olmayan sertifikalar istemci kimlik doğrulaması ve kayıt aracısı dahil her işte kullanılabilir.' `
            -Oneri 'Şablona sadece gereken EKU''ları ver; kayıt hakkını daralt ya da onay iste.'
    }

    Invoke-AdcsKontrol 'K42' 'ESC3 kayit aracisi sablonlari' {
        $liste = @($riskliKayit | Where-Object { $_.TalepAjani -and $_.Korumasiz } | Select-Object $sablonSutunlari)
        Add-Bulgu -Kod 'K42' -Baslik 'ESC3 kayit aracisi sablonlari' -Seviye 'YUKSEK' -Nesneler $liste `
            -Aciklama 'Certificate Request Agent sertifikası alan biri başka kullanıcılar adına sertifika isteyebilir.' `
            -Oneri 'Kayıt hakkını sadece kayıt aracısı olacak hesaplara ver; CA''da "Restrict enrollment agents" ayarını kullan.'
    }

    Invoke-AdcsKontrol 'K43' 'ESC4 dusuk yetkililerin degistirebildigi sablonlar' {
        $liste = @($Sablonlar | Where-Object { $_.DusukYetkiliYazma } | Select-Object (@('Yayinda') + $sablonSutunlari))
        $seviye = 'ORTA'
        if (@($liste | Where-Object { $_.Yayinda }).Count -gt 0) { $seviye = 'YUKSEK' }
        Add-Bulgu -Kod 'K43' -Baslik 'ESC4 dusuk yetkililerin degistirebildigi sablonlar' -Seviye $seviye -Nesneler $liste `
            -Aciklama 'Şablonu değiştirebilen biri onu ESC1''e çevirip etki alanını ele geçirebilir. Sadece yazma bitleri (WriteDacl, WriteOwner, WriteProperty, GenericAll) sayılır, okuma hakları sayılmaz.' `
            -Oneri 'Şablonun Security sekmesinden düşük yetkili gruplara verilen yazma/tam denetim haklarını kaldır.'
    }

    Invoke-AdcsKontrol 'K44' 'ESC9 guvenlik uzantisi kapali sablonlar' {
        $liste = @($riskliKayit | Where-Object { $_.GuvenlikUzantisiYok -and $_.IstemciDogrulama -and $_.Korumasiz } | Select-Object $sablonSutunlari)
        Add-Bulgu -Kod 'K44' -Baslik 'ESC9 guvenlik uzantisi kapali sablonlar' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama 'CT_FLAG_NO_SECURITY_EXTENSION, sertifikaya SID uzantısını koymaz; hesabın UPN''ini değiştirebilen biri başka hesap adına sertifika alabilir. DC''lerde güçlü sertifika eşleme (StrongCertificateBindingEnforcement=2) bu riski büyük ölçüde kapatır.' `
            -Oneri 'Bayrağı kaldır (certutil -dstemplate <şablon> msPKI-Enrollment-Flag -0x80000) ve DC''lerde tam zorlama moduna geç.'
    }

    Invoke-AdcsKontrol 'K45' 'ESC15 surum 1 sablonlarda konu istekte' {
        $liste = @($riskliKayit | Where-Object { $_.SemaSurumu -eq 1 -and $_.KonuIstekte -and $_.Korumasiz } | Select-Object $sablonSutunlari)
        Add-Bulgu -Kod 'K45' -Baslik 'ESC15 surum 1 sablonlarda konu istekte' -Seviye 'ORTA' -Nesneler $liste `
            -Aciklama 'Güncellenmemiş CA''larda sürüm 1 şablonlara istekte farklı uygulama ilkeleri (örneğin Client Authentication) eklenebilir (CVE-2024-49019, Kasım 2024 güncellemesiyle kapatıldı). Örnek: yerleşik WebServer şablonu.' `
            -Oneri 'CA sunucularının Kasım 2024 sonrası güncellemelerini doğrula. Şablonu çoğaltıp sürüm 2+ yap ya da kayıt hakkını daralt.'
    }

    # --- ADCS sertifika yetkilileri (CA sunucuları) -------------------------

    if ($ProtokolKontrolleriniAtla) {
        Write-Log 'CA sunucusu kontrolleri (K46-K49) atlandı.'
    }
    elseif ($AdcsHata) {
        Invoke-AdcsKontrol 'K46' 'Kurumsal CA lar' { }
    }
    else {
        Write-Host ''
        Write-Log "CA sunucuları okunuyor ($($caListesi.Count) CA)..."

        # CA hakları: 1 = ManageCA (CA yöneticisi), 2 = ManageCertificates (sertifika yöneticisi)
        $CaSatirlari = @()
        foreach ($ca in $caListesi) {
          try {
            $sunucu = Get-Deger $ca 'dNSHostName'
            if (-not $sunucu) { throw 'CA nesnesinde dNSHostName yok.' }
            Write-Log -Seviye DETAY -Mesaj "CA okunuyor: $($ca.Name) @ $sunucu"
            $sonuc = Invoke-UzakOkuma -Bilgisayar $sunucu -Okuyucu $CaOkuyucu -Arguman $ca.Name

            $san2 = $null; $editMetin = ''; $yoneticiler = @(); $sertYoneticileri = @(); $dusukYetkiler = @()
            if ($sonuc.Veri) {
                $v = $sonuc.Veri
                if ($null -ne $v['EditFlags']) {
                    $ef = [int64]$v['EditFlags']
                    $san2 = ($ef -band 0x40000) -ne 0
                    $editMetin = '0x{0:X}' -f $ef
                }
                if ($v['Guvenlik']) {
                    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([byte[]]$v['Guvenlik']), 0
                    foreach ($ace in $sd.DiscretionaryAcl) {
                        if ("$($ace.AceQualifier)" -ne 'AccessAllowed') { continue }
                        $sid = $ace.SecurityIdentifier.Value
                        $maske = [int]$ace.AccessMask
                        $ad = Get-SidAdi $sid
                        if ($maske -band 1) { $yoneticiler += $ad }
                        if ($maske -band 2) { $sertYoneticileri += $ad }
                        if ($DusukYetkililer.ContainsKey($sid) -and ($maske -band 3)) {
                            $h = @()
                            if ($maske -band 1) { $h += 'ManageCA' }
                            if ($maske -band 2) { $h += 'ManageCertificates' }
                            $dusukYetkiler += '{0}: {1}' -f $ad, ($h -join '+')
                        }
                    }
                }
            }

            $http = Test-WebKaydi "http://$sunucu/certsrv/"
            $https = Test-WebKaydi "https://$sunucu/certsrv/"

            $CaSatirlari += [pscustomobject][ordered]@{
                CA                   = $ca.Name
                Sunucu               = $sunucu
                Yontem               = $sonuc.Yontem
                OkumaHatasi          = $sonuc.Hata
                IlkeModulu           = if ($sonuc.Veri) { $sonuc.Veri['IlkeModulu'] } else { '' }
                EditFlags            = $editMetin
                SAN2Acik             = $san2
                ManageCA             = (@($yoneticiler | Sort-Object -Unique) -join ', ')
                ManageCertificates   = (@($sertYoneticileri | Sort-Object -Unique) -join ', ')
                DusukYetkiliCAHakki  = (@($dusukYetkiler | Sort-Object -Unique) -join '; ')
                WebKaydiHTTP         = $http.Durum
                WebKaydiHTTPS        = $https.Durum
                HttpNtlm             = $http.Ntlm
                HttpsNtlm            = $https.Ntlm
            }
          }
          catch {
            # Bu CA'yı "okunamadı" say, diğerlerine devam et.
            $CaSatirlari += [pscustomobject][ordered]@{
                CA = $ca.Name; Sunucu = (Get-Deger $ca 'dNSHostName'); Yontem = ''; OkumaHatasi = $_.Exception.Message
                IlkeModulu = ''; EditFlags = ''; SAN2Acik = $null; ManageCA = ''; ManageCertificates = ''
                DusukYetkiliCAHakki = ''; WebKaydiHTTP = ''; WebKaydiHTTPS = ''; HttpNtlm = $false; HttpsNtlm = $false
            }
          }
        }
        $okunan = @($CaSatirlari | Where-Object { -not $_.OkumaHatasi })

        Invoke-Kontrol 'K46' 'Kurumsal CA lar' {
            $liste = @($CaSatirlari | Select-Object CA, Sunucu, Yontem, IlkeModulu, EditFlags, ManageCA, ManageCertificates, WebKaydiHTTP, WebKaydiHTTPS, OkumaHatasi)
            $okunamayan = @($CaSatirlari | Where-Object { $_.OkumaHatasi })
            $seviye = 'BILGI'
            $aciklama = 'Kurumsal CA''lar, CA yöneticileri ve web kaydı durumu. ManageCA ve ManageCertificates sahipleri Tier 0 sayılmalı.'
            if ($okunamayan.Count -gt 0) {
                $seviye = 'ORTA'
                $aciklama += " $($okunamayan.Count) CA'nın kayıt defteri okunamadı; ESC6/ESC7 bunlar için eksik (OkumaHatasi sütununa bak)."
            }
            Add-Bulgu -Kod 'K46' -Baslik 'Kurumsal CA lar' -Seviye $seviye -Nesneler $liste `
                -Aciklama $aciklama `
                -Oneri 'CA yöneticisi haklarını sadece PKI yöneticilerine ver; CA sunucularını DC''ler gibi Tier 0 olarak koru.'
        }

        Invoke-Kontrol 'K47' 'ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2' {
            if ($caListesi.Count -gt 0 -and $okunan.Count -eq 0) { throw 'Hiçbir CA''nın kayıt defteri okunamadı (bkz. K46).' }
            $liste = @($okunan | Where-Object { $_.SAN2Acik } | Select-Object CA, Sunucu, IlkeModulu, EditFlags, Yontem)
            Add-Bulgu -Kod 'K47' -Baslik 'ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2' -Seviye 'YUKSEK' -Nesneler $liste `
                -Aciklama 'Bu bayrak açıksa kayıt yapabilen herkes, istek özniteliğiyle (SAN) sertifikaya istediği kullanıcıyı yazdırabilir; her istemci kimlik doğrulama şablonu ESC1''e dönüşür. Mayıs 2022 güçlü sertifika eşleme güncellemeleri etkisini azaltır, ama DC''ler uyumluluk modundaysa ya da ESC9/ESC16 ile birleşince hâlâ sömürülebilir.' `
                -Oneri 'certutil -config "<CA sunucusu>\<CA adı>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 ve ardından CertSvc hizmetini yeniden başlat.'
        }

        Invoke-Kontrol 'K48' 'ESC7 dusuk yetkililerde CA yonetim hakki' {
            if ($caListesi.Count -gt 0 -and $okunan.Count -eq 0) { throw 'Hiçbir CA''nın kayıt defteri okunamadı (bkz. K46).' }
            $liste = @($okunan | Where-Object { $_.DusukYetkiliCAHakki } | Select-Object CA, Sunucu, DusukYetkiliCAHakki, ManageCA, ManageCertificates, Yontem)
            Add-Bulgu -Kod 'K48' -Baslik 'ESC7 dusuk yetkililerde CA yonetim hakki' -Seviye 'KRITIK' -Nesneler $liste `
                -Aciklama 'ManageCA hakkı olan biri CA ayarlarını (örneğin ESC6 bayrağını) değiştirebilir ve kendini sertifika yöneticisi yapabilir; ManageCertificates ile bekleyen ya da reddedilmiş istekleri onaylayabilir. İkisi de etki alanını ele geçirmeye yeter.' `
                -Oneri 'CA özelliklerinde Security sekmesinden düşük yetkili gruplara verilen Manage CA / Issue and Manage Certificates haklarını kaldır.'
        }

        Invoke-Kontrol 'K49' 'ESC8 NTLM kabul eden web kaydi' {
            $liste = @($CaSatirlari | Where-Object { $_.HttpNtlm -or $_.HttpsNtlm } | ForEach-Object {
                    [pscustomobject]@{
                        CA            = $_.CA
                        Sunucu        = $_.Sunucu
                        WebKaydiHTTP  = $_.WebKaydiHTTP
                        WebKaydiHTTPS = $_.WebKaydiHTTPS
                        Durum         = if ($_.HttpNtlm) { 'HTTP üzerinden NTLM: relay''e açık' } else { 'Sadece HTTPS: EPA (Extended Protection) açık mı doğrula' }
                    }
                })
            $seviye = 'ORTA'
            if (@($liste | Where-Object { $_.WebKaydiHTTP -like '401*' -and $_.Durum -like 'HTTP *' }).Count -gt 0) { $seviye = 'YUKSEK' }
            Add-Bulgu -Kod 'K49' -Baslik 'ESC8 NTLM kabul eden web kaydi' -Seviye $seviye -Nesneler $liste `
                -Aciklama 'Web kaydı (certsrv) NTLM kabul ediyorsa bir DC''yi kimlik doğrulamaya zorlayıp (PetitPotam, PrinterBug) NTLM''ini buraya relay eden saldırgan DC adına sertifika alır ve etki alanını ele geçirir.' `
                -Oneri 'Kullanılmıyorsa Web Enrollment rolünü kaldır. Kullanılıyorsa sadece HTTPS kullan, IIS''te Extended Protection for Authentication''ı Required yap ve NTLM''i kapat (sadece Kerberos/Negotiate:Kerberos).'
        }
    }

    # --- sunucu protokol kontrolleri --------------------------------------

    if ($ProtokolKontrolleriniAtla) {
        Write-Log 'Sunucu protokol kontrolleri (K31-K36) atlandı.'
    }
    else {
        $hedefler = New-Object System.Collections.Generic.List[object]
        foreach ($dc in $DCler) {
            $ad = Get-Deger $dc 'DNSHostName'
            if (-not $ad) { $ad = $dc.Name }
            $rol = if ((Get-Deger $dc 'PrimaryGroupID') -eq 521) { 'RODC' } else { 'DC' }
            $hedefler.Add(@{ Ad = $ad; Rol = $rol; OS = Get-Deger $dc 'OperatingSystem' })
        }
        foreach ($s in $EkSunucular) {
            if ($s) { $hedefler.Add(@{ Ad = $s; Rol = 'Ek sunucu'; OS = '' }) }
        }

        Write-Host ''
        Write-Log "Sunucu protokol ayarları okunuyor ($($hedefler.Count) sunucu)..."
        $protokolSatirlari = @()
        $okunamayanlar = @()
        foreach ($h in $hedefler) {
            Write-Log -Seviye DETAY -Mesaj "Okunuyor: $($h.Ad)"
            $sonuc = Get-ProtokolAyarlari $h.Ad
            if ($sonuc.Veri) {
                $protokolSatirlari += ConvertTo-ProtokolSatiri -Sunucu $h.Ad -Rol $h.Rol -IsletimSistemi $h.OS -Sonuc $sonuc
            }
            else {
                $okunamayanlar += [pscustomobject]@{ Sunucu = $h.Ad; Rol = $h.Rol; Hata = $sonuc.Hata }
            }
        }
        if ($protokolSatirlari.Count -gt 0) {
            $protokolSatirlari | Export-Csv -Path (Join-Path $CiktiKlasoru 'Sunucu_Protokol_Ayarlari.csv') -NoTypeInformation -Encoding $CsvKodlama -UseCulture
        }

        Invoke-Kontrol 'K31' 'Protokol ayarlari okunamayan sunucular' {
            Add-Bulgu -Kod 'K31' -Baslik 'Protokol ayarlari okunamayan sunucular' -Seviye 'ORTA' -Nesneler $okunamayanlar `
                -Aciklama 'Bu sunuculara ne WinRM ne de uzak kayıt defteri ile bağlanılabildi; K32-K35 bunlar için eksik.' `
                -Oneri 'Yönetici yetkisini, WinRM''i (Enable-PSRemoting) ya da Remote Registry hizmetini ve güvenlik duvarını kontrol et.'
        }

        Invoke-Kontrol 'K32' 'TLS 1.0 - 1.1 acik sunucular' {
            if ($protokolSatirlari.Count -eq 0) { throw 'Hiçbir sunucudan veri alınamadı (bkz. K31).' }
            $liste = @($protokolSatirlari | Where-Object { $_.TlsEskiAcik } |
                Select-Object Sunucu, Rol, IsletimSistemi, Build, TLS10Sunucu, TLS11Sunucu, TLS10Istemci, TLS11Istemci, Yontem)
            Add-Bulgu -Kod 'K32' -Baslik 'TLS 1.0 - 1.1 acik sunucular' -Seviye 'ORTA' -Nesneler $liste `
                -Aciklama 'TLS 1.0 ve 1.1 bilinen zafiyetleri olan, desteği bitmiş protokollerdir. DC''lerde LDAPS, RDP ve ADFS/WinRM-HTTPS gibi servisler bunları kabul eder.' `
                -Oneri "SCHANNEL\Protocols\TLS 1.0\Server ve TLS 1.1\Server altında Enabled=0, DisabledByDefault=1 ayarla (GPO ya da IISCrypto). Önce eski istemcileri (.NET 4.5 öncesi, eski Java, yazıcı/tarayıcılar) kontrol et."
        }

        Invoke-Kontrol 'K33' 'SMBv1 acik sunucular' {
            if ($protokolSatirlari.Count -eq 0) { throw 'Hiçbir sunucudan veri alınamadı (bkz. K31).' }
            $liste = @($protokolSatirlari | Where-Object { $_.Smb1Acik } |
                Select-Object Sunucu, Rol, IsletimSistemi, SMB1Sunucu, SMB1Istemci, Yontem)
            $seviye = 'ORTA'
            if (@($protokolSatirlari | Where-Object { $_.Smb1Acik -and $_.Rol -ne 'Ek sunucu' -and $_.SMB1Sunucu -eq 'Açık' }).Count -gt 0) { $seviye = 'YUKSEK' }
            Add-Bulgu -Kod 'K33' -Baslik 'SMBv1 acik sunucular' -Seviye $seviye -Nesneler $liste `
                -Aciklama 'SMBv1 EternalBlue/WannaCry gibi saldırıların kullandığı, şifreleme ve güçlü imzalama desteklemeyen eski protokoldür.' `
                -Oneri 'Önce kullananları bul (Set-SmbServerConfiguration -AuditSmb1Access $true, olay 3000). Sonra Set-SmbServerConfiguration -EnableSMB1Protocol $false ve SMB1 özelliğini kaldır.'
        }

        Invoke-Kontrol 'K34' 'SMB imzalama zorunlu degil' {
            if ($protokolSatirlari.Count -eq 0) { throw 'Hiçbir sunucudan veri alınamadı (bkz. K31).' }
            $liste = @($protokolSatirlari | Where-Object { -not $_.SunucuImzaZorunlu -or -not $_.IstemciImzaZorunlu } |
                Select-Object Sunucu, Rol, IsletimSistemi, SmbImzaSunucu, SmbImzaIstemci, Yontem)
            $seviye = 'ORTA'
            if (@($protokolSatirlari | Where-Object { $_.Rol -ne 'Ek sunucu' -and -not $_.SunucuImzaZorunlu }).Count -gt 0) { $seviye = 'YUKSEK' }
            Add-Bulgu -Kod 'K34' -Baslik 'SMB imzalama zorunlu degil' -Seviye $seviye -Nesneler $liste `
                -Aciklama 'İmzalama zorunlu değilse SMB oturumları NTLM relay ile ele geçirilebilir. DC''lerde sunucu tarafı imzalama mutlaka zorunlu olmalı.' `
                -Oneri '"Microsoft network server/client: Digitally sign communications (always)" ilkesini Etkin yap. DC''lerde Default Domain Controllers Policy''de, diğer sunucularda ayrı bir GPO ile.'
        }

        Invoke-Kontrol 'K35' 'NTLMv1 kabul eden veya gonderen sunucular' {
            if ($protokolSatirlari.Count -eq 0) { throw 'Hiçbir sunucudan veri alınamadı (bkz. K31).' }
            $liste = @($protokolSatirlari | Where-Object { $_.NTLMv1 } |
                Select-Object Sunucu, Rol, IsletimSistemi, LmCompatibilityLevel, NTLMv1, Yontem)
            $seviye = 'ORTA'
            if (@($liste | Where-Object { $_.NTLMv1 -like '*gönderiyor*' }).Count -gt 0) { $seviye = 'YUKSEK' }
            Add-Bulgu -Kod 'K35' -Baslik 'NTLMv1 kabul eden veya gonderen sunucular' -Seviye $seviye -Nesneler $liste `
                -Aciklama 'LmCompatibilityLevel 5''ten küçük bir DC NTLMv1 kimlik doğrulamasını kabul eder; NTLMv1 yanıtları kolayca kırılır ve relay edilebilir. 3''ten küçükse sunucunun kendisi LM/NTLMv1 gönderir.' `
                -Oneri '"Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM" (5). DC''lerde açmadan önce -NtlmV1OlayTara ile kullananları bul.'
        }

        if ($NtlmV1OlayTara) {
            Invoke-Kontrol 'K36' "NTLMv1 oturum acmalari (son $OlayGun gun)" {
                $liste = @()
                $taranamayan = @()
                foreach ($h in @($hedefler | Where-Object { $_.Rol -ne 'Ek sunucu' })) {
                    Write-Log -Seviye DETAY -Mesaj "NTLMv1 olayları taranıyor: $($h.Ad)"
                    try { $liste += @(Get-NtlmV1Oturumlari $h.Ad) }
                    catch { $taranamayan += "$($h.Ad) ($($_.Exception.Message))" }
                }
                $dcSayisi = @($hedefler | Where-Object { $_.Rol -ne 'Ek sunucu' }).Count
                if ($dcSayisi -gt 0 -and $taranamayan.Count -eq $dcSayisi) { throw "Hiçbir DC taranamadı: $($taranamayan -join '; ')" }
                $aciklama = "Son $OlayGun günde DC'lerde NTLMv1 ile yapılan oturum açmalar (olay 4624). Bunlar LmCompatibilityLevel 5'e çıkınca çalışmayacak istemcilerdir."
                if ($taranamayan.Count -gt 0) { $aciklama += " Taranamayan DC'ler: $($taranamayan -join '; ')." }
                if (@($liste | Where-Object { $_.SinirDolu }).Count -gt 0) { $aciklama += " Bazı DC'lerde $MaxOlay olay sınırına ulaşıldı; liste eksik olabilir." }
                Add-Bulgu -Kod 'K36' -Baslik "NTLMv1 oturum acmalari (son $OlayGun gun)" -Seviye 'ORTA' -Nesneler $liste `
                    -Aciklama $aciklama `
                    -Oneri 'Listelenen makine ve uygulamaları NTLMv2 ya da Kerberos kullanacak şekilde güncelle; sonra DC''lerde seviye 5''e geç.'
            }
        }

        Invoke-Kontrol 'K37' 'LDAP imzalama ve kanal baglama' {
            $dcSatirlari = @($protokolSatirlari | Where-Object { $_.Rol -ne 'Ek sunucu' })
            if ($dcSatirlari.Count -eq 0) { throw 'Hiçbir DC''den veri alınamadı (bkz. K31).' }
            $liste = @($dcSatirlari | Where-Object { -not $_.LdapImzaZorunlu -or $_.LdapKanalSeviye -lt 2 } |
                Select-Object Sunucu, Rol, IsletimSistemi, Build, LdapImza, LdapKanalBaglama, LdapTanilama, LdapIstemciImza, Yontem)
            $seviye = 'ORTA'
            if (@($dcSatirlari | Where-Object { -not $_.LdapImzaZorunlu }).Count -gt 0) { $seviye = 'YUKSEK' }
            Add-Bulgu -Kod 'K37' -Baslik 'LDAP imzalama ve kanal baglama' -Seviye $seviye -Nesneler $liste `
                -Aciklama 'İmzalama zorunlu değilse DC''ye imzasız LDAP ile bağlanılabilir; bu, NTLM relay ile DC''de değişiklik yapmaya (RBCD, shadow credentials, grup üyeliği) kapı açar. Kanal bağlama "her zaman" değilse LDAPS üzerinden relay mümkündür. Server 2025''te varsayılanlar değişmiş olabilir; tanımsız görünen değerleri GPO''dan doğrula.' `
                -Oneri 'Önce -LdapOlayTara ile imzasız bağlanan istemcileri bul. Sonra "Domain controller: LDAP server signing requirements" = Require signing, "LDAP server channel binding token requirements" = Always. İstemcilerde "Network security: LDAP client signing requirements" = Negotiate signing ya da üstü.'
        }

        if ($LdapOlayTara) {
            Invoke-Kontrol 'K38' "Imzasiz LDAP baglantilari (son $OlayGun gun)" {
                $liste = @()
                $taranamayan = @()
                $dcHedefler = @($hedefler | Where-Object { $_.Rol -ne 'Ek sunucu' })
                foreach ($h in $dcHedefler) {
                    Write-Log -Seviye DETAY -Mesaj "LDAP olayları taranıyor: $($h.Ad)"
                    try { $liste += @(Get-LdapImzasizBaglantilar $h.Ad) }
                    catch { $taranamayan += "$($h.Ad) ($($_.Exception.Message))" }
                }
                if ($dcHedefler.Count -gt 0 -and $taranamayan.Count -eq $dcHedefler.Count) { throw "Hiçbir DC taranamadı: $($taranamayan -join '; ')" }
                # Toplamı 0 olan 2887 kayıtları bulgu değildir.
                $liste = @($liste | Where-Object { $_.Adet -gt 0 })

                $aciklama = "Son $OlayGun günde DC'lere imzasız SASL ya da düz metin simple bind ile yapılan LDAP bağlantıları. Bunlar imzalama zorunlu olunca çalışmayacak istemcilerdir."
                $taniKapali = @($protokolSatirlari | Where-Object { $_.Rol -ne 'Ek sunucu' -and $_.LdapTanilama -like 'Kapalı*' } | ForEach-Object { $_.Sunucu })
                if ($taniKapali.Count -gt 0) {
                    $aciklama += " Şu DC'lerde LDAP tanılama günlüğü kapalı, sadece günlük toplam (2887) görülür, istemci IP'leri (2889) görülmez: $($taniKapali -join ', ')."
                }
                if ($taranamayan.Count -gt 0) { $aciklama += " Taranamayan DC'ler: $($taranamayan -join '; ')." }
                if (@($liste | Where-Object { $_.SinirDolu }).Count -gt 0) { $aciklama += " Bazı DC'lerde $MaxOlay olay sınırına ulaşıldı; liste eksik olabilir." }
                Add-Bulgu -Kod 'K38' -Baslik "Imzasiz LDAP baglantilari (son $OlayGun gun)" -Seviye 'ORTA' -Nesneler $liste `
                    -Aciklama $aciklama `
                    -Oneri 'İstemci IP''lerini görmek için DC''de HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events = 2 yap (DWORD; birkaç gün sonra 0''a geri al). Listelenen uygulamaları imzalı LDAP ya da LDAPS kullanacak şekilde düzelt.'
            }
        }
    }

    # --- özet ----------------------------------------------------------------

    $sirali = @($Bulgular | Sort-Object @{ Expression = { $SeviyeSirasi[$_.Seviye] } }, Kod)
    $sirali | Export-Csv -Path (Join-Path $CiktiKlasoru '00_Bulgular.csv') -NoTypeInformation -Encoding $CsvKodlama -UseCulture

    $sayac = [ordered]@{}
    foreach ($s in 'KRITIK', 'YUKSEK', 'ORTA', 'DUSUK', 'BILGI', 'HATA', 'TAMAM') {
        $sayac[$s] = @($Bulgular | Where-Object { $_.Seviye -eq $s }).Count
    }

    $ozet = New-Object System.Text.StringBuilder
    [void]$ozet.AppendLine('AD Güvenlik Denetimi')
    [void]$ozet.AppendLine('====================')
    [void]$ozet.AppendLine("Tarih            : $($Simdi.ToString('yyyy-MM-dd HH:mm'))")
    [void]$ozet.AppendLine("Etki alanı       : $($Domain.DNSRoot) ($($Domain.NetBIOSName))")
    [void]$ozet.AppendLine("Orman            : $($Forest.Name)")
    [void]$ozet.AppendLine("Düzeyler         : etki alanı $($Domain.DomainMode), orman $($Forest.ForestMode)")
    [void]$ozet.AppendLine("DC sayısı        : $($DCler.Count)")
    [void]$ozet.AppendLine("Kullanıcı        : $($Kullanicilar.Count) (etkin $($EtkinKullanicilar.Count))")
    [void]$ozet.AppendLine("Bilgisayar       : $($Bilgisayarlar.Count)")
    $digerAyricalikli = $Ayricaliklilar.Count - $AyricalikliKullanicilar.Count
    [void]$ozet.AppendLine("Ayrıcalıklı hesap: $($AyricalikliKullanicilar.Count) kullanıcı, $digerAyricalikli diğer (gMSA / bilgisayar)")
    [void]$ozet.AppendLine("Çalıştıran       : $([Environment]::UserDomainName)\$([Environment]::UserName) @ $([Environment]::MachineName)")
    [void]$ozet.AppendLine("Eşikler          : inaktif $InaktifGun gün, parola $ParolaYasGun gün, krbtgt $KrbtgtYasGun gün")
    [void]$ozet.AppendLine('')
    [void]$ozet.AppendLine(('Sonuç: ' + (($sayac.Keys | ForEach-Object { "$_ $($sayac[$_])" }) -join ', ')))
    [void]$ozet.AppendLine('')
    foreach ($b in $sirali) {
        [void]$ozet.AppendLine(('[{0}] {1} - {2} ({3})' -f $b.Seviye, $b.Kod, $b.Kontrol, $b.Adet))
        if ($b.Seviye -ne 'TAMAM') {
            [void]$ozet.AppendLine("    $($b.Aciklama)")
            if ($b.Oneri) { [void]$ozet.AppendLine("    Öneri: $($b.Oneri)") }
            if ($b.Dosya) { [void]$ozet.AppendLine("    Ayrıntı: $($b.Dosya)") }
        }
        [void]$ozet.AppendLine('')
    }
    [void]$ozet.AppendLine('Not: Son giriş tarihleri lastLogonTimestamp''ten gelir ve 9-14 gün gecikebilir.')

    $ozetDosyasi = Join-Path $CiktiKlasoru '00_Ozet.txt'
    [System.IO.File]::WriteAllText($ozetDosyasi, $ozet.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    Write-Host ''
    Write-Log ('Sonuç: ' + (($sayac.Keys | ForEach-Object { "$_ $($sayac[$_])" }) -join ', '))
    Write-Log "Özet: $ozetDosyasi"
}
catch {
    Write-Log -Seviye HATA -Mesaj ("Satır {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    exit 1
}
