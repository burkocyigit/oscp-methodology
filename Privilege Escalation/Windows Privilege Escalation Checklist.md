# Windows Privilege Escalation Checklist

Work from top to bottom after obtaining a low-privilege foothold. Follow applicable branches, verify every finding manually, and record what evidence justifies each step. After gaining credentials, privileges, or access to another host, repeat **03. Credential and access review**.

## 01. Stabilize and orient

- [ ] **01.1** Confirm the target is in scope and note any constraints on tools, exploit methods, or service disruption.
- [ ] **01.2** Establish a stable, interactive shell suitable for reliable enumeration and file transfer.
- [ ] **01.3** Record the current username, hostname, domain or workgroup, and current integrity or privilege level.
- [ ] **01.4** Record the operating system edition, version, build, architecture, and installed patch level.
- [ ] **01.5** Review current-user groups, privileges, and accessible directories.
- [ ] **01.6** Record network interfaces, routes, listening services, and active connections.
- [ ] **01.7** Identify installed applications, running processes, and services that may run with elevated privileges.
- [ ] **01.8** Preserve useful output and note which finding led to each follow-up.

## 02. Run and validate automated enumeration

- [ ] **02.1** Run a Windows privilege-enumeration tool appropriate to the target and save its findings.
- [ ] **02.2** Run a second enumeration method when useful to cross-check important findings.
- [ ] **02.3** Review high-signal results first: privileges, services, writable paths, credentials, scheduled tasks, and unusual binaries.
- [ ] **02.4** Manually verify every promising result, including the effective permissions, execution context, and required trigger.
- [ ] **02.5** Compare any suggested operating-system exploit with the exact build and patch level before considering it.

## 03. Credential and access review

- [ ] **03.1** Search accessible files and user profiles for credentials, secrets, keys, configuration files, and backups.
- [ ] **03.2** Inspect unattended installation and system setup files for stored credentials.
- [ ] **03.3** Review PowerShell history and other command-history files for passwords, tokens, or connection details.
- [ ] **03.4** Inspect application and web-server configuration files for connection strings and service credentials.
- [ ] **03.5** Check saved remote-connection profiles and configuration files for RDP, SSH, PuTTY, WinSCP, or remote-management credentials.
- [ ] **03.6** Review interesting documents and application data in accessible user profiles.
- [ ] **03.7** If XAMPP is installed, inspect its leftover password files and configuration for database credentials.
- [ ] **03.8** If SAM and SYSTEM hive backups are accessible, preserve both and analyze them together for local account hashes.
- [ ] **03.9** If administrator or SYSTEM access is already available, assess whether SAM, SYSTEM, SECURITY, or LSASS-derived material can reveal reusable credentials.
- [ ] **03.10** For each recovered credential, identify whether it is local, domain, service, or application-specific.
- [ ] **03.11** Test recovered credentials only against authorized services and hosts; record successful account-host combinations.
- [ ] **03.12** If a credential works as another user, obtain an authorized session as that user and repeat **01. Stabilize and orient**, **02. Run and validate automated enumeration**, and this section.

## 04. Check user rights and token privileges

- [ ] **04.1** Review the current account's assigned privileges and identify enabled or available token rights.
- [ ] **04.2** If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is present, check whether a compatible local impersonation path applies to the OS build and service context.
  - [ ] **04.2.1** Verify the resulting identity is SYSTEM before continuing.
  - [ ] **04.2.2** If the first compatible method fails, assess another applicable impersonation technique rather than assuming the privilege is unusable.
- [ ] **04.3** If SeBackupPrivilege is present, determine whether it permits reading protected files or registry hives; collect and analyze only material needed for the next step.
- [ ] **04.4** If SeRestorePrivilege is present, assess whether an in-scope protected file or service component can be safely replaced to gain higher privileges.
- [ ] **04.5** If SeTakeOwnershipPrivilege is present, determine whether taking ownership of a relevant file or service enables a controlled permission change.
- [ ] **04.6** If SeLoadDriverPrivilege is present, check whether a suitable, vulnerable driver path is applicable and permitted.
- [ ] **04.7** If SeDebugPrivilege or local administrator access is present, assess whether process memory or LSASS can yield credentials for authorized lateral movement.
- [ ] **04.8** If impersonation fails, check whether a usable privileged token is present and whether the target session can be impersonated.
- [ ] **04.9** If no usable privilege is found, continue with **05. Inspect services**, **06. Check installers and scheduled execution**, and **07. Inspect files and applications**.

## 05. Inspect services and service permissions

- [ ] **05.1** Inventory services, their executable paths, startup behavior, and the identities under which they run.
- [ ] **05.2** Check whether any service executable or its containing directory is writable by the current account.
- [ ] **05.3** Check whether service configuration permissions allow changing the executable path, account, or other security-relevant settings.
- [ ] **05.4** If a service path contains spaces and is unquoted, verify whether a candidate path location is writable and could be selected during service startup.
- [ ] **05.5** If a writable service executable or path is identified, confirm the service runs with higher privileges and determine how it can be restarted or triggered.
- [ ] **05.6** If the service is exploitable, make only the required in-scope change and verify the resulting identity.
- [ ] **05.7** Restore the original service configuration or executable when appropriate and permitted.

## 06. Check installers, scheduled tasks, and startup execution

- [ ] **06.1** Check both machine-wide and current-user installer policy settings for an elevated installation condition.
  - [ ] **06.1.1** If both required settings are enabled, verify whether an authorized installer-based escalation path applies.
- [ ] **06.2** Enumerate scheduled tasks and record their run-as identity, trigger, action, and referenced files.
- [ ] **06.3** If a privileged task references a file or directory writable by the current account, verify its trigger and whether a controlled change can be tested.
- [ ] **06.4** Inspect startup applications and scripts for elevated execution of writable content.
- [ ] **06.5** Verify any resulting privilege change and restore modified task or startup content when appropriate.

## 07. Inspect files, directories, and applications

- [ ] **07.1** Identify writable directories and files used by privileged services, applications, scripts, or scheduled tasks.
- [ ] **07.2** Inspect installed applications and their versions for insecure configurations, outdated components, and stored credentials.
- [ ] **07.3** Inspect running processes for privileged applications loading code or configuration from writable locations.
- [ ] **07.4** If a privileged process searches for a missing DLL in a writable directory, verify the loading conditions and whether a compatible hijack path applies.
- [ ] **07.5** If a privileged application invokes another program through a modifiable search path, assess whether a safe, controlled path-abuse test is applicable.
- [ ] **07.6** If a file or directory has weak permissions, confirm the exact privileged consumer, execution condition, and impact before modifying it.
- [ ] **07.7** If a privileged accessibility utility can be replaced through a legitimate file privilege, verify the conditions and use only the documented, in-scope route.

## 08. Review process memory and local credential material

- [ ] **08.1** If local administrator, SYSTEM, or SeDebugPrivilege is available, determine whether live sessions contain useful credentials or authentication tickets.
- [ ] **08.2** If live collection is unsuitable, determine whether an authorized process-memory dump can be analyzed offline.
- [ ] **08.3** If local hive backups are present or can be collected with granted privileges, preserve the required companion hives before analysis.
- [ ] **08.4** Distinguish local account hashes from domain account material and identify which can support further access.
- [ ] **08.5** Test recovered credentials or hashes against appropriate in-scope hosts, then repeat **03. Credential and access review**.

## 09. Consider operating-system exploits only as a fallback

- [ ] **09.1** Record the exact Windows build, architecture, and patch level before evaluating a kernel or operating-system exploit.
- [ ] **09.2** Cross-check any suggested vulnerability against reliable evidence and verify all exploit prerequisites.
- [ ] **09.3** Prefer a lower-risk, manually verified service, privilege, credential, or scheduled-task path when one is available.
- [ ] **09.4** If an operating-system exploit is the only viable route, assess crash risk and use a matching test environment when feasible.
- [ ] **09.5** Verify the resulting privilege and preserve the evidence supporting the exploit choice.

## 10. Verify, repeat, and report

- [ ] **10.1** Confirm the final identity, groups, and effective privileges directly on the target.
- [ ] **10.2** Collect the required proof and record the precise path from the initial user to the elevated account.
- [ ] **10.3** After any new credential, user context, or privilege, repeat **01. Stabilize and orient**, **02. Run and validate automated enumeration**, and **03. Credential and access review**.
- [ ] **10.4** Document the enumeration evidence that justified each escalation attempt, the prerequisites, the result, and its impact.
- [ ] **10.5** Restore temporary changes when appropriate and permitted; clearly document any change that cannot safely be reversed.
- [ ] **10.6** Keep exploit attempts within scope and avoid unnecessary persistence or disruptive changes.
