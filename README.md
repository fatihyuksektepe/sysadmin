# sysadmin

[English](#english) | [Türkçe](#türkçe)

## English

Bash and PowerShell scripts I use in day-to-day sysadmin work. I clean them up and share them in case they save someone else a few minutes. Bash scripts are for Linux, PowerShell scripts for Windows.

### Scripts

| Script | What it does |
| --- | --- |
| [bash/sunucu-saglik-ozeti.sh](bash/sunucu-saglik-ozeti.sh) | Shows a Linux server's health on one screen: disk and inode usage, memory, swap, load, failed systemd units, pending updates and pending reboot. Read only. |
| [bash/wazuh-ajan-durumu.sh](bash/wazuh-ajan-durumu.sh) | Pulls all agents from the Wazuh API and lists the problematic ones. Read only. |
| [bash/wazuh-yapilandirma-denetimi.sh](bash/wazuh-yapilandirma-denetimi.sh) | Audits a Wazuh server's configuration: manager, API, indexer, Filebeat, dashboard, services and certificates. Read only. |
| [powershell/AD-Guvenlik-Denetimi.ps1](powershell/AD-Guvenlik-Denetimi.ps1) | General security audit for Active Directory, writes a CSV per check plus a summary. Read only. |

The messages and help text inside the scripts are in Turkish.

### Running a script

Read the script first, and try it on a test machine before you run it anywhere that matters. Some of them may change system settings or restart services.

Bash:

```bash
chmod +x script.sh && ./script.sh
```

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Script.ps1
```

### Disclaimer

The scripts are provided as is, without any warranty. You are responsible for what they do on your systems.

### Issues

If a script breaks or behaves oddly on your setup, open an issue and include the OS version and the exact error. Pull requests are not accepted.

### License

Released under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

## Türkçe

Gündelik sistem yöneticiliği işlerinde kullandığım Bash ve PowerShell scriptleri. Temizleyip paylaşıyorum, belki başkasının da birkaç dakikasını kurtarır. Bash scriptleri Linux, PowerShell scriptleri Windows içindir.

### Scriptler

| Script | Ne yapar |
| --- | --- |
| [bash/sunucu-saglik-ozeti.sh](bash/sunucu-saglik-ozeti.sh) | Linux sunucunun durumunu tek ekranda gösterir: disk ve inode doluluğu, bellek, swap, yük, hata durumundaki systemd birimleri, bekleyen güncellemeler ve yeniden başlatma ihtiyacı. Salt okunur. |
| [bash/wazuh-ajan-durumu.sh](bash/wazuh-ajan-durumu.sh) | Wazuh API'sinden bütün ajanları çeker ve sorunlu olanları listeler. Salt okunur. |
| [bash/wazuh-yapilandirma-denetimi.sh](bash/wazuh-yapilandirma-denetimi.sh) | Wazuh sunucusunun yapılandırmasını denetler: manager, API, indexer, Filebeat, dashboard, servisler ve sertifikalar. Salt okunur. |
| [powershell/AD-Guvenlik-Denetimi.ps1](powershell/AD-Guvenlik-Denetimi.ps1) | Active Directory için genel güvenlik denetimi yapar, her kontrol için bir CSV ve bir özet çıkarır. Salt okunur. |

### Script çalıştırma

Çalıştırmadan önce scripti oku, önemli bir ortama dokunmadan önce de bir test makinesinde dene. Bazıları sistem ayarlarını değiştirebilir ya da servisleri yeniden başlatabilir.

Bash:

```bash
chmod +x script.sh && ./script.sh
```

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Script.ps1
```

### Sorumluluk reddi

Scriptler olduğu gibi sunulur, herhangi bir garanti verilmez. Sistemlerinizde yaptıkları işlerden siz sorumlusunuz.

### Issues

Bir script sizin ortamınızda hata veriyorsa ya da beklenmedik davranıyorsa issue açın, işletim sistemi sürümünü ve aldığınız hatayı olduğu gibi yazın. Pull request kabul edilmiyor.

### Lisans

GNU Affero General Public License v3.0 ile yayınlanmıştır. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
