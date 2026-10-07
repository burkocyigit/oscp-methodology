# Windows Privilege Escalation Methodology

Use this in priority order: baseline, token privilege checks, service/task abuse, credential hunting, and only then higher-risk or exploit-heavy branches. Confirm every finding manually, capture the user flag before PE, and capture the elevated flag immediately after success.

## 1. Baseline and user-flag check

- [ ] Capture `whoami /all`, hostname, system build, IP config, route table, and listening ports before escalating.
- [ ] Record the exact OS/architecture and confirm the current user, groups, and enabled token privileges.
- [ ] Read the user flag (`local.txt` or the exam-specified path) and record it before changing privilege.
- [ ] Use [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md) and [Initial Foothold](initial-foothold.md) for the foothold-specific path and shell selection logic.

```powershell
whoami /all
hostname
systeminfo
Get-CimInstance Win32_OperatingSystem | Select Caption,Version,OSArchitecture
ipconfig /all
route print
netstat -ano
```

## 2. Prioritize token privileges and PE paths

- [ ] Check `whoami /priv` and treat token privileges as the first branch rather than a generic service audit.
- [ ] Validate each privilege by the exact target object and exploitation path; do not guess based on a scanner warning alone.
- [ ] Before using a PrintSpoofer/GodPotato-family technique, confirm the OS build and service context.
- [ ] For `SeBackupPrivilege` and `SeRestorePrivilege`, only operate on a protected file or service when the exact outcome is known and in-scope.

| Privilege | High-priority path |
|---|---|
| `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege` | Use the most compatible token-impersonation path and verify the resulting identity. |
| `SeBackupPrivilege` | Follow the SeBackupPrivilege approach and confirm the exact files or hashes recovered. |
| `SeRestorePrivilege` / `SeTakeOwnershipPrivilege` | Use a controlled file or service change only when the impact is proven. |
| `SeDebugPrivilege` | Only dump LSASS through a permitted path and keep all sensitive output under strict controls. |
| `SeLoadDriverPrivilege` / `SeManageVolumePrivilege` | Treat these as high-risk branches; confirm OS and tool prerequisites first. |

- [ ] Use [Privilege Abuses](Active%20Directory/Privilege%20Abuses.md) for SeBackupPrivilege and DC-related backup paths.

## 3. Enumerate services, tasks, and writable execution paths

### Service and binary checks

- [ ] Review service names, start users, state, and binary paths.
- [ ] Confirm whether the service binary or parent directory is writable by the current user and whether it executes as SYSTEM/admin.
- [ ] Check quoting and service restart behavior before modifying a service path.

```powershell
Get-CimInstance Win32_Service | Select Name,StartName,State,PathName
sc.exe qc <service>
icacls "<service-binary-or-parent-directory>"
```

### Scheduled tasks and startup items

- [ ] Enumerate scheduled tasks and startup items; check if a privileged task points to a writable script, file, or directory.
- [ ] Record the trigger condition, run-as identity, and whether the path is actually used.

```powershell
schtasks /query /fo LIST /v
icacls "<task-action-script-or-binary>"
```

### Installer and DLL hijack checks

- [ ] Check the Windows Installer policy values for `AlwaysInstallElevated` before trying a MSI-based route.
- [ ] For DLL or binary hijacking, identify a privileged process that loads from a writable or untrusted path and confirm the trigger.

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
```

## 4. Hunt for local credentials and secrets

- [ ] Search in order: PowerShell history, profiles, app configs, XAMPP files, unattended/sysprep files, saved connections, tasks, service commands, registry autologon, backups, and accessible shares.
- [ ] Review process arguments or environment variables only when readable and relevant to the current user or service.
- [ ] Validate each recovered credential against in-scope hosts and services before reusing it.

```powershell
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
cmdkey /list
Get-ChildItem C:\ -Include unattend.xml,sysprep.xml,web.config,*.rdp,confCons.xml,*.bak,*.old -File -Recurse -ErrorAction SilentlyContinue
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
Get-CimInstance Win32_Process | Select ProcessId,Name,CommandLine
```

- [ ] For XAMPP, inspect `C:\xampp\phpMyAdmin\config.inc.php`, `mysql\bin\my.ini`, Apache config, `htdocs`, and `passwords.txt`.
- [ ] For mRemoteNG, check `confCons.xml` and decrypt only if the relevant path and environment support it.
- [ ] If a local admin or backup privilege is confirmed, use an authorized SAM/SYSTEM/SECURITY or LSASS collection method.

```bash
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

- [ ] Treat hashes and dumps as sensitive and keep only the evidence needed for the exam report.

## 5. Check app and database-specific paths

- [ ] If the foothold is an app or database service, verify the process identity and effective token before escalating further.
- [ ] For MSSQL, confirm the server role and `xp_cmdshell` state before invoking a command path.
- [ ] For XAMPP/MySQL, confirm `FILE` privilege, `secure_file_priv`, write path, and service identity before trying a file-write route.
- [ ] Follow [XAMPP](Web%20Application/XAMPP.md), [SQL Injection](Web%20Application/SQL%20Injection.md), [PostgreSQL](Enumeration/PostgreSQL.md), and [Common Ports](Enumeration/Common%20Ports.md) for service-specific prerequisites.

## 6. Validate PE and capture the elevated flag

- [ ] Before running an exploit, document the exact privilege, ACL, task, service, or vulnerable version that supports the path.
- [ ] Use a proof command first when possible.
- [ ] After the privilege gain, confirm `whoami /all` and the expected elevated identity on the same host.
- [ ] Immediately locate and read that host's elevated flag (`proof.txt`, `root.txt`, or the exam-specified path) before pivoting.
- [ ] Record the impacted object, proof output, and any file or service change made.
- [ ] If this is an AD member or DC, hand off recovered domain rights to [AD Set Methodology](ad-set.md); local SYSTEM alone does not establish domain-admin ownership.
- [ ] Do not add persistence or make additional domain-wide changes unless explicitly required by the exam.

- [ ] If a PE attempt fails, revisit the exact prerequisite that failed and do not rerun the same destructive attempt unchanged.
