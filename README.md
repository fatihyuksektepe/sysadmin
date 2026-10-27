# sysadmin

[English](#english) | [Türkçe](#türkçe)

## English

Bash and PowerShell scripts I use in day-to-day sysadmin work. I clean them up and share them in case they save someone else a few minutes. Bash scripts are for Linux, PowerShell scripts for Windows.

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
