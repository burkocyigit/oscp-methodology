# Linux Privilege Escalation Checklist

Work from top to bottom after obtaining a low-privilege foothold. Follow applicable branches, verify every finding manually, and record what evidence justifies each step. After gaining credentials, privileges, or access to another host, repeat **03. Credential review**.

## 01. Stabilize and orient

- [ ] **01.1** Confirm the target is in scope and note any constraints on exploit methods or service disruption.
- [ ] **01.2** Establish a stable interactive shell suitable for enumeration and file transfer.
- [ ] **01.3** Record the current username, user and group identifiers, hostname, and effective privileges.
- [ ] **01.4** Record the operating system, distribution, kernel version, and processor architecture.
- [ ] **01.5** Review local accounts and identify which have interactive login shells.
- [ ] **01.6** Record network interfaces, routes, listening services, and accessible internal services.
- [ ] **01.7** Check sudo permissions early; if a permitted command can run with elevated rights, go to **05. Sudo permissions**.
- [ ] **01.8** Preserve useful output and note which finding led to each follow-up.

## 02. Run and validate automated enumeration

- [ ] **02.1** Run an appropriate Linux privilege-enumeration tool and review its results manually.
- [ ] **02.2** Use a second enumeration method when useful to cross-check important findings.
- [ ] **02.3** Review high-signal results first: sudo rights, credentials, writable files, SUID/SGID binaries, capabilities, scheduled jobs, and groups.
- [ ] **02.4** Verify each candidate manually, including its effective permissions, execution context, and required trigger.
- [ ] **02.5** Treat automated kernel-exploit suggestions as leads; verify the exact kernel and distribution conditions before use.

## 03. Credential review

- [ ] **03.1** Search accessible configuration and secret files for passwords, keys, tokens, and connection strings.
- [ ] **03.2** Inspect shell, database, and application history files for credentials or useful commands.
- [ ] **03.3** Review web application and service configuration files for database or service credentials.
- [ ] **03.4** Search for backups, old copies, editor swap files, and version-control history that may expose secrets.
- [ ] **03.5** Check for SSH keys, private keys, authorized keys, and password-manager files.
- [ ] **03.6** Inspect database dumps and local database files; if credentials are found, determine whether they also work for a local user or database account.
- [ ] **03.7** If a Git repository is accessible, inspect its history for removed credentials or older configuration.
- [ ] **03.8** If process information is readable, inspect command arguments and environment variables for secrets.
- [ ] **03.9** Check accessible cloud, container, and CI credential files.
- [ ] **03.10** Identify whether each discovered credential belongs to a local user, service, application, or external system.
- [ ] **03.11** Test recovered credentials only against authorized local accounts and services; record successful combinations.
- [ ] **03.12** If a password is reused by another local user, obtain an authorized session as that user and repeat **01. Stabilize and orient**, **02. Run and validate automated enumeration**, and this section.

## 04. Check account groups and execution context

- [ ] **04.1** Identify the groups assigned to the current user and whether any grant administrative capabilities.
- [ ] **04.2** If the user belongs to a container-management group, assess whether that membership provides access to the host filesystem or elevated execution.
- [ ] **04.3** If the user belongs to a group that can mount filesystems or manage devices, identify the exact permitted operations and assess their impact.
- [ ] **04.4** Check whether the session is inside a container or restricted environment before interpreting filesystem, process, and network results.
- [ ] **04.5** If a new user context becomes available, repeat **01. Stabilize and orient**, **02. Run and validate automated enumeration**, and **03. Credential review**.

## 05. Sudo permissions

- [ ] **05.1** Review permitted sudo commands, required authentication, run-as identities, command arguments, and preserved environment variables.
- [ ] **05.2** If a permitted binary can execute or read files as a more privileged user, check its documented behavior against a trusted privilege-escalation reference.
- [ ] **05.3** If a permitted custom script is present, inspect its contents, arguments, called programs, file permissions, and environment assumptions.
- [ ] **05.4** If the script or a dependency is writable, verify whether a controlled modification can be triggered with elevated privileges.
- [ ] **05.5** If environment variables are preserved, determine whether they can influence a permitted privileged program or its loaded libraries.
- [ ] **05.6** If a sudo path succeeds, verify the resulting identity and proceed to **14. Verify, repeat, and report**.

## 06. Check SUID and SGID programs

- [ ] **06.1** Enumerate SUID and SGID files and compare them with expected system binaries.
- [ ] **06.2** Prioritize custom, unusual, recently installed, or writable SUID/SGID programs.
- [ ] **06.3** For a known binary, check the SUID-specific behavior in a trusted reference; do not assume sudo techniques apply to SUID execution.
- [ ] **06.4** For an unknown binary, inspect its strings, library calls, and execution behavior in a safe manner.
- [ ] **06.5** If the binary invokes another program by a relative path or relies on an unsafe search path, verify whether a controlled path-hijack condition exists.
- [ ] **06.6** If a buffer-handling flaw is suspected, verify the architecture and protections before considering a proof of concept.
- [ ] **06.7** If a SUID path succeeds, verify the effective identity and proceed to **14. Verify, repeat, and report**.

## 07. Check file capabilities

- [ ] **07.1** Enumerate file capabilities and identify the exact executable, capability, and effective privilege it grants.
- [ ] **07.2** If a capability allows changing user IDs, verify whether the specific executable can use it to obtain a more privileged identity.
- [ ] **07.3** If a capability permits bypassing file read restrictions, identify sensitive files that become accessible and whether they contain useful credentials.
- [ ] **07.4** If a capability permits system administration or mounting, assess whether an in-scope filesystem or container escape path applies.
- [ ] **07.5** Verify the resulting access and continue with **03. Credential review**.

## 08. Inspect scheduled jobs and cron

- [ ] **08.1** Enumerate system-wide and user-specific scheduled jobs, their run-as identities, schedules, commands, and environment.
- [ ] **08.2** If an elevated job runs a script or executable writable by the current user, verify the trigger and impact before changing it.
- [ ] **08.3** If an elevated job invokes a program through a relative path or weak search path, assess PATH hijacking.
- [ ] **08.4** If a scheduled job uses broad filename patterns, assess whether its tool interprets filenames as options.
- [ ] **08.5** Observe scheduled execution when needed to confirm the actual process, timing, and environment.
- [ ] **08.6** If a scheduled-job path succeeds, verify the resulting identity and proceed to **14. Verify, repeat, and report**.

## 09. Check PATH and writable directories

- [ ] **09.1** Review the current search path and identify writable directories.
- [ ] **09.2** Identify privileged scripts and jobs that call programs without an absolute path.
- [ ] **09.3** If a writable directory is searched before the legitimate program location, verify whether a controlled replacement would be executed in the privileged context.
- [ ] **09.4** Confirm that the relevant script or job can actually be triggered before relying on a PATH-hijack path.
- [ ] **09.5** Check whether privileged processes load libraries from writable directories or honor modifiable library-path settings.
- [ ] **09.6** If a path or library hijack succeeds, verify the resulting identity and proceed to **14. Verify, repeat, and report**.

## 10. Check NFS and mounted resources

- [ ] **10.1** Inspect available NFS exports and mount options, using local configuration or permitted remote enumeration.
- [ ] **10.2** If an export is writable and does not restrict root access appropriately, assess whether a controlled privileged-file path applies.
- [ ] **10.3** Verify the identity mapping and mount behavior before relying on an NFS-based escalation.
- [ ] **10.4** If a mounted-resource path succeeds, verify the resulting identity and proceed to **14. Verify, repeat, and report**.

## 11. Check writable sensitive files

- [ ] **11.1** Check permissions on account databases, authentication configuration, sudo policy, and other security-sensitive files.
- [ ] **11.2** If an account database is writable, determine whether the change would grant unauthorized privileges and whether it can be tested safely.
- [ ] **11.3** If a password-hash store is writable, determine whether a controlled modification is possible and what account it would affect.
- [ ] **11.4** If sudo policy is writable, verify whether a minimal authorized change would provide elevated execution.
- [ ] **11.5** Search for other writable configuration files consumed by privileged services or scheduled jobs.
- [ ] **11.6** If a sensitive-file path succeeds, verify the resulting access and proceed to **14. Verify, repeat, and report**.

## 12. Check wildcard and argument injection

- [ ] **12.1** Identify privileged scripts or jobs that pass wildcard-expanded filenames to archiving, synchronization, ownership, permission, or similar utilities.
- [ ] **12.2** Verify the working directory is writable and understand how the invoked utility parses filenames and options.
- [ ] **12.3** If option-like filenames can be interpreted as arguments, confirm the trigger and impact before attempting a controlled test.
- [ ] **12.4** If the path succeeds, verify the resulting identity and proceed to **14. Verify, repeat, and report**.

## 13. Check services, kernels, containers, and internal access

- [ ] **13.1** Inventory running services and identify privileged services with outdated versions, unsafe configuration, or writable scripts and dependencies.
- [ ] **13.2** Enumerate local listening services and identify applications available only from the target itself.
- [ ] **13.3** If an internal-only service is relevant, determine whether an authorized port-forwarding path would allow safe enumeration from the attacking system.
- [ ] **13.4** If container evidence is present, determine the container runtime, current capabilities, mounts, and accessible host resources.
- [ ] **13.5** If the user can control a container runtime, assess whether that access exposes the host filesystem or grants host-level privileges.
- [ ] **13.6** If elevated container capabilities or writable control interfaces are present, verify whether a relevant escape path applies to the specific configuration.
- [ ] **13.7** Record the exact kernel, distribution, architecture, and patch context before evaluating kernel or service exploits.
- [ ] **13.8** Treat kernel exploits as a last resort; verify prerequisites, assess crash risk, and prefer a safer manual path when available.
- [ ] **13.9** If a kernel, service, or container path succeeds, verify the resulting identity and proceed to **14. Verify, repeat, and report**.

## 14. Verify, repeat, and report

- [ ] **14.1** Confirm the final effective user ID, groups, and privileges directly on the target.
- [ ] **14.2** Collect the required proof and record the precise path from the initial user to the elevated account.
- [ ] **14.3** After any new credential, user context, or privilege, repeat **01. Stabilize and orient**, **02. Run and validate automated enumeration**, and **03. Credential review**.
- [ ] **14.4** Document the enumeration evidence that justified each escalation attempt, the prerequisites, the result, and its impact.
- [ ] **14.5** Restore temporary changes when appropriate and permitted; clearly document any change that cannot safely be reversed.
- [ ] **14.6** Keep exploit attempts within scope and avoid unnecessary persistence or disruptive changes.
