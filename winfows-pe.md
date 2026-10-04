# Windows Privilege Escalation Methodology

Follow this after landing a low-privilege Windows shell. Verify each scanner finding manually, keep the evidence that selected the path, and distinguish local SYSTEM/admin from domain privilege. The requested filename is `winfows-pe.md`.

## 0. Baseline and flag capture

```powershell
whoami /all
hostname
systeminfo
Get-CimInstance Win32_OperatingSystem | Select Caption,Version,OSArchitecture
ipconfig /all
route print
netstat -ano
```

Record current user, groups, privileges, hostname/domain, build/patches, architecture, interfaces, and listening ports. Immediately locate/read the user flag (`local.txt` or exam-specified path) and record its exact value before PE.

## 1. Automated and manual enumeration

Transfer and run one or two permitted enumeration tools; save their complete output. Treat these tools as leads, not proof.

```powershell
.\winPEASx64.exe quiet servicesinfo filesinfo > winpeas.txt
powershell -ExecutionPolicy Bypass -File .\PrivescCheck.ps1
whoami /priv
whoami /groups
net user
net localgroup administrators
schtasks /query /fo LIST /v
Get-CimInstance Win32_Service | Select Name,StartName,State,PathName
```

Cross-check installed applications, hotfixes, processes, service account, binary/parent-directory ACLs, registry settings, task actions, and file ownership. For a custom finding, establish both that it is writable and that a higher-privileged process actually executes or consumes it.

## 2. Check high-value token privileges first

`whoami /priv` determines whether these branches are available. A privilege marked Disabled may still be present in the token; confirm whether the specific technique can enable/use it.

| Privilege | Evidence-led path |
|---|---|
| `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege` | Check OS/build and service context; select a compatible PrintSpoofer/GodPotato-family technique from the source notes. Verify returned identity. |
| `SeBackupPrivilege` | If present, follow the SeBackupPrivilege notes to obtain authorized backup-mode access to protected files; on a DC the path may recover directory hashes. Confirm scope and handling of the extracted data. |
| `SeRestorePrivilege` / `SeTakeOwnershipPrivilege` | Identify an exact protected file/service whose modification changes execution or access; verify impact before writing. |
| `SeDebugPrivilege` | If already high enough to access LSASS, use a permitted dump-and-parse path; protect and remove sensitive dump files according to exam rules. |
| `SeLoadDriverPrivilege` / `SeManageVolumePrivilege` | Check exact OS/build/tool prerequisites and writable effect; treat driver/DLL approaches as high-risk, evidence-required branches. |

For SeBackupPrivilege and domain-controller data, see [Privilege Abuses](Active%20Directory/Privilege%20Abuses.md); use only where the host, privilege, and exam scope support it. Do not assume local backup rights imply domain compromise.

## 3. Services, scheduled tasks, and writable execution paths

### Service configuration and binary paths

```powershell
Get-CimInstance Win32_Service | Select Name,StartName,State,PathName
sc.exe qc <service>
icacls "<service-binary-or-parent-directory>"
```

For each candidate, prove the service runs as SYSTEM/admin, identify whether its binary, parent directory, service configuration, or restart action is writable to you, and check quoting/space behavior. Confirm that you can cause a safe restart or wait for a documented restart. Do not replace a production/system binary based only on a scanner warning.

### Scheduled tasks and startup items

```powershell
schtasks /query /fo LIST /v
icacls "<task-action-script-or-binary>"
```

Follow only if a privileged task points to a file or directory you can modify, or a task can be changed/triggered by your account. Record the run-as identity, schedule, and trigger condition.

### AlwaysInstallElevated and application paths

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
```

This branch requires both policy values to be enabled. For PATH/DLL hijacking, find a privileged process/service loading from a user-writable directory or searching an uncontrolled path; identify the missing DLL/export or searched binary and prove it is loaded on a trigger.

## 4. Credential hunting and local secrets

Search in a scoped order: current user's PowerShell history and profile, other readable profiles, application/web/database configs, XAMPP files, unattended/sysprep files, saved connections, scheduled task/service command lines, registry autologon, backups, and accessible shares. Review process arguments/environment only where readable. Use `findstr`/PowerShell search and inspect `.git` history when present.

```powershell
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
cmdkey /list
Get-ChildItem C:\ -Include unattend.xml,sysprep.xml,web.config,*.rdp,confCons.xml,*.bak,*.old -File -Recurse -ErrorAction SilentlyContinue
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
Get-CimInstance Win32_Process | Select ProcessId,Name,CommandLine
```

For XAMPP, check `C:\xampp\phpMyAdmin\config.inc.php`, `mysql\bin\my.ini`, `apache\conf`, `htdocs` app configs, and `passwords.txt`. For mRemoteNG, find `confCons.xml` and check the relevant source instructions for decryption. Validate found credentials against services and hosts in scope, documenting account context and results.

If local admin/SYSTEM or applicable backup rights are confirmed, use a permitted SAM/SYSTEM/SECURITY or LSASS collection method. Parse offline hives using the requested Impacket entry-point syntax:

```bash
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

Treat dumps and hashes as sensitive; retain only evidence needed for the exam report. A local SAM hash is not automatically a domain hash.

## 5. Database and application-specific branches

If the foothold is an app or database service, verify the process identity before escalating further. A webshell may run as a low-privilege service account or as SYSTEM; check `whoami` and its token. For MSSQL, confirm the login's server role and `xp_cmdshell` state before using it. For XAMPP/MySQL, confirm `FILE` privilege, `secure_file_priv`, write path, and service identity. Follow [XAMPP](Web%20Application/XAMPP.md), [SQL Injection](Web%20Application/SQL%20Injection.md), [PostgreSQL](Enumeration/PostgreSQL.md), and [Common Ports](Enumeration/Common%20Ports.md) for service-specific prerequisites.

## 6. Validate PE and capture the elevated flag

Before running an exploit, write down the precise observation that supports it: privilege present, weak ACL, task/service identity, vulnerable version, and trigger. Use a proof command first where possible. After success:

1. Confirm `whoami /all` and the expected elevated identity on the same host.
2. Immediately locate and read that host's elevated flag (`proof.txt`, `root.txt`, or exam-specified path). Record the exact value and evidence before pivoting.
3. Record the path, affected object/service, proof output, and any change made.
4. If this is an AD member/DC, hand recovered domain credentials/rights to [AD Set Methodology](ad-set.md); local SYSTEM alone does not establish domain-admin rights.
5. Do not establish persistence or make additional domain-wide changes unless explicitly required by the exam.

If a PE attempt fails, revisit the prerequisite that failed (privilege, ACL, architecture, service trigger, patch level); do not rerun a destructive attempt unchanged.

## Source notes

- [Windows Privilege Escalation](Privilege%20Escalation/Windows%20Privilege%20Escalation.md)
- [Privilege Abuses and SeBackupPrivilege](Active%20Directory/Privilege%20Abuses.md)
- [Windows Credential Hunting](Active%20Directory/Credential%20Hunting.md)
- [AD Set Methodology](ad-set.md)
- [Initial Foothold](initial-foothold.md)
- [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md)
- [File Transfers](File%20Transfers/File%20Transfers.md)
- [Password Attacks](Password%20Attacks/Password%20Attacks.md)
- [Windows Lateral Movement](Lateral%20Movement/Windows.md)
- [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md)
- [XAMPP](Web%20Application/XAMPP.md)
- [SQL Injection](Web%20Application/SQL%20Injection.md)
- [PostgreSQL](Enumeration/PostgreSQL.md)
- [Common Ports](Enumeration/Common%20Ports.md)
- [Windows Persistence](Persistence/Windows%20Persistence.md)
