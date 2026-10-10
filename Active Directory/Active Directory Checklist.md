# Active Directory Exam Checklist

Work from top to bottom, following only the branches that apply. Keep a record of each finding, the account or host it belongs to, how it was obtained, and the next step it enables. After every new credential, privilege, or foothold, return to **07. Credentialed Enumeration** and **08. Attack-Path Review**.

## 01. Prepare and establish context

- [ ] **01.1** Confirm the exam scope, permitted targets, and any restrictions before interacting with the environment.
- [ ] **01.2** Record the target IPs, hostnames, domain name, suspected domain controller, and any known subnets.
- [ ] **01.3** Resolve or record the domain controller's hostname and domain names so that host-based and Kerberos authentication can be used consistently.
- [ ] **01.4** Check clock alignment before using Kerberos; correct time discrepancies if ticket-based authentication fails.
- [ ] **01.5** Start an evidence log. Record why each enumeration or exploitation step is justified and retain useful results for the report.

## 02. Map the network and identify services

- [ ] **02.1** Scan the in-scope hosts for TCP services, versions, and default-script findings; record all open ports for later review.
- [ ] **02.2** Check common UDP services where relevant and add findings to the host notes.
- [ ] **02.3** Identify likely domain controllers from DNS, LDAP, Kerberos, SMB, and host naming information.
- [ ] **02.4** Note SMB signing status and whether any hosts may be relevant to relay paths.
- [ ] **02.5** If DNS is available, check whether a zone transfer exposes hostnames or additional targets.

## 03. Enumerate without credentials

- [ ] **03.1** Check whether SMB permits anonymous or guest access; enumerate accessible shares and their contents if it does.
- [ ] **03.2** Check for an SMB null session and enumerate domain information, users, groups, and privileges where permitted.
- [ ] **03.3** Check whether LDAP anonymous bind is allowed; if so, collect domain objects and inspect user descriptions and other free-text attributes for exposed credentials.
- [ ] **03.4** Build and validate a username list using available sources, including Kerberos username enumeration when appropriate.
- [ ] **03.5** If anonymous or guest access exposes files, inspect every readable share and note any credentials, scripts, backups, or configuration files.

## 04. Find an initial foothold

- [ ] **04.1** If no domain credentials are available, look for an initial foothold on an in-scope workstation or service rather than assuming the domain controller is the entry point.
- [ ] **04.2** If a web or application foothold exists, inspect application configuration and backup files for database or service credentials.
- [ ] **04.3** If XAMPP is present, inspect its configuration, database settings, and leftover password files for credentials.
- [ ] **04.4** If XAMPP database credentials are found, determine whether they work locally or remotely and whether the database account has file-write capability.
- [ ] **04.5** If database file writing is possible and permitted by scope, determine whether an accessible web directory can be used to gain execution; verify the resulting identity and privileges.
- [ ] **04.6** If an unusual service such as WHOIS or POP3 is exposed, enumerate it for usernames or messages that may disclose another login.
- [ ] **04.7** If a mailbox or service yields credentials, test them against relevant in-scope services and record each successful account-host combination.
- [ ] **04.8** If a user account is marked as requiring a password change, use the permitted password-change path before retrying authentication. ([XAMPP](Active%20Directory/XAMPP.md), [Other](./Other.md))
- [ ] **04.9** If remote management is unavailable for a valid account, check other exposed and authorized access paths, such as file shares, remote execution services, or RDP.
- [ ] **04.10** If the foothold is Linux, review the operating-system and privilege-escalation context, including the installed sudo version, before selecting a local escalation path.
- [ ] **04.11** If a known sudo weakness appears applicable, verify its prerequisites and impact before attempting escalation; confirm the resulting identity and collect the required proof.

## 05. Hunt for credentials on every foothold

- [ ] **05.1** Search accessible files and directories for passwords, secrets, tokens, keys, configuration files, database settings, and backups.
- [ ] **05.2** Inspect application-specific configuration, deployment files, shell or PowerShell history, unattended installation files, and service configuration for credentials.
- [ ] **05.3** Review process environments, scheduled tasks, cron jobs, service definitions, and saved credentials for secrets or useful execution context.
- [ ] **05.4** Check for password-manager databases, browser credential stores, SSH material, and other user-profile artifacts.
- [ ] **05.5** On Windows, review PowerShell history and remote-connection-manager configuration files; if an encrypted connection password is found, determine whether the notes' decryption path applies.
- [ ] **05.6** If local administrator or SYSTEM access is already available, consider collecting local SAM, SECURITY, and SYSTEM material for offline credential analysis.
- [ ] **05.7** If credential material is found, classify it as a password, NTLM hash, Kerberos ticket, certificate, or local-only secret before selecting the next authentication test.
- [ ] **05.8** Test each newly recovered credential or hash against appropriate in-scope services and then return to **07. Credentialed Enumeration**.

## 06. Enumerate SMB shares and hunt domain-wide credentials

- [ ] **06.1** Enumerate shares with every available authentication context: anonymous, guest, and each valid account.
- [ ] **06.2** Review every accessible share recursively; prioritize backup, user, IT, scripts, software, and administrative content.
- [ ] **06.3** Search readable share contents for credentials, private keys, database files, registry hives, archives, scripts, and configuration files.
- [ ] **06.4** Inspect SYSVOL and NETLOGON for Group Policy Preferences, logon scripts, scheduled tasks, and embedded service credentials.
- [ ] **06.5** If a Group Policy Preferences password value is found, determine whether it can be recovered and validate the resulting credential.
- [ ] **06.6** If an accessible share contains SAM and SYSTEM backups, preserve both and analyze them together; include SECURITY when cached domain credentials or LSA secrets may be relevant.
- [ ] **06.7** If a share contains NTDS or other domain-controller backup material, preserve the required companion files and analyze them offline.
- [ ] **06.8** After every recovered credential or hash, test appropriate SMB, WinRM, and other exposed services and return to **07. Credentialed Enumeration**.

## 07. Credentialed Enumeration

- [ ] **07.1** Validate each credential or hash against the domain controller and other discovered hosts; distinguish domain accounts from local accounts.
- [ ] **07.2** Enumerate domain users, groups, logged-on users, and accessible shares with each valid account.
- [ ] **07.3** Collect detailed LDAP/domain information, including privileged users, group memberships, descriptions, and other potentially sensitive attributes.
- [ ] **07.4** Inspect user descriptions and other free-text fields for passwords, hints, or account-specific information.
- [ ] **07.5** Crawl accessible shares for files and inspect SYSVOL and NETLOGON again with the authenticated context.
- [ ] **07.6** Enumerate writable AD objects and record the exact principal, target object, and right for every discovered permission.
- [ ] **07.7** Collect domain data for graph analysis and mark the accounts and computers you control as owned.

## 08. Review attack paths after every change in access

- [ ] **08.1** Review the shortest paths from owned principals to Domain Admins and other high-value targets.
- [ ] **08.2** Review paths from each owned account or computer, not only direct paths to Domain Admins.
- [ ] **08.3** Prioritize short, verifiable paths such as password-reset rights, privileged-group membership, sensitive-attribute read rights, and replication rights.
- [ ] **08.4** After each password change, group change, newly obtained credential, or new host foothold, repeat **07. Credentialed Enumeration** and this section.

## 09. Check for roasting opportunities

- [ ] **09.1** Check for accounts with service principal names and identify their owners, privileges, and group memberships; record the domain SID early if ticket-based paths may be useful. ([Roasting](./Roasting.md), [Silver Ticket Attack](./Silver%20Ticket%20Attack.md))
- [ ] **09.2** If service accounts are present, request the applicable service tickets and attempt offline password recovery.
- [ ] **09.3** If a service-account password is recovered, validate it and immediately review that account's group memberships, local-admin access, and attack paths; then return to **07** and **08**.
- [ ] **09.4** Check the user list for accounts that do not require Kerberos pre-authentication.
- [ ] **09.5** If roastable pre-authentication-disabled accounts are found, request their challenge material and attempt offline password recovery.
- [ ] **09.6** Validate any recovered password and resume **07. Credentialed Enumeration**.
- [ ] **09.7** If you control a user's SPN attribute, consider targeted Kerberoasting and remove any temporary SPN afterward.

## 10. Password spraying and credential reuse

- [ ] **10.1** Before spraying, determine the account lockout policy and choose an approach that stays within the allowed threshold.
- [ ] **10.2** Clean and validate the username list; avoid spraying against invalid or duplicate account names.
- [ ] **10.3** Build a small, evidence-based candidate-password list from discovered patterns, organization context, and recovered material.
- [ ] **10.4** Test one candidate at a time across the appropriate in-scope accounts and services, recording successes and failures.
- [ ] **10.5** If hashes rather than plaintext passwords are available, test them against the relevant accounts and services using the appropriate authentication method.
- [ ] **10.6** Test all newly discovered credentials and hashes for reuse across SMB, WinRM, RDP, and other exposed services; record local-versus-domain scope.
- [ ] **10.7** After every successful authentication, return to **07. Credentialed Enumeration** and **08. Attack-Path Review**.

## 11. Abuse AD permissions and sensitive attributes

- [ ] **11.1** For every exploitable ACL, confirm the exact target object and right before changing anything.
- [ ] **11.2** If you can reset a user's password, decide whether the account's service role or restrictions make a reset risky; use an appropriate permitted password-change path and consider a non-password-changing path if appropriate. ([ACL Abuse](./ACL%20Abuse.md), [Other](./Other.md))
- [ ] **11.3** If you can write a user's SPN, consider targeted Kerberoasting and remove the temporary SPN afterward.
- [ ] **11.4** If you can add yourself to a privileged group, add only the controlled account needed and obtain fresh authentication material before testing the new membership.
- [ ] **11.5** If you have WriteOwner, take ownership, grant only the rights needed for the next step, then continue with the applicable user, group, computer, GPO, or domain-object branch.
- [ ] **11.6** If you have WriteDACL, grant only the required right and then follow the corresponding abuse path.
- [ ] **11.7** If you can read LAPS credentials, identify the specific computer they belong to and test them as that computer's local administrator.
- [ ] **11.8** If you can read a gMSA password, recover its usable credential material and check the account's privileges and reachable hosts.
- [ ] **11.9** If you can write a target user's key-credential attribute, consider Shadow Credentials; preserve the original state and remove the added key when appropriate.
- [ ] **11.10** If a DC computer object is writable, check the Shadow Credentials path first; if it fails, consider the documented RBCD path and then attempt replication using the resulting DC identity.
- [ ] **11.11** After every ACL change or newly obtained identity, repeat **07. Credentialed Enumeration** and **08. Attack-Path Review**.

## 12. Check delegation paths

- [ ] **12.1** Enumerate unconstrained delegation, constrained delegation, and existing resource-based constrained delegation across users and computers.
- [ ] **12.2** If a compromised host has unconstrained delegation, assess whether a privileged account can be induced to authenticate to it and whether a usable ticket is captured.
- [ ] **12.3** If a controlled account has constrained delegation, identify the exact allowed service principals and check whether the intended impersonated account is protected from delegation.
- [ ] **12.4** If RBCD is already configured for a controlled principal, identify its target and use the documented service-ticket path to test access.
- [ ] **12.5** If no usable delegation is configured but you can write the target computer object, check the machine-account quota and whether you already control a suitable principal.
- [ ] **12.6** If the machine-account quota permits and no suitable principal is controlled, create a controlled computer account; otherwise use an existing controlled principal where supported.
- [ ] **12.7** Set RBCD only on the target object you are authorized to modify, obtain the appropriate service ticket, and verify access on the target.
- [ ] **12.8** If a delegation path succeeds, assess whether the resulting identity can access shares, execute remotely, or perform directory replication; then return to **07** and **08**.
- [ ] **12.9** Remove temporary delegation settings, accounts, and ACL grants when appropriate and preserve evidence of the original and restored state.

## 13. Check Group Policy abuse

- [ ] **13.1** If you have write rights on a GPO, determine which organizational units and computers it affects before modifying it.
- [ ] **13.2** If the GPO applies to a useful target, use the documented GPO abuse path to obtain the required local privilege.
- [ ] **13.3** Account for policy refresh timing; trigger a refresh only if you have authorized access to the affected computer, otherwise allow for the normal refresh interval.
- [ ] **13.4** Verify the resulting local group membership or access level, then return to **07. Credentialed Enumeration** and **08. Attack-Path Review**.

## 14. Check Active Directory Certificate Services

- [ ] **14.1** Determine whether a certificate authority and certificate templates are present; enumerate them and review all reported vulnerabilities before selecting a path.
- [ ] **14.2** If the enrollment path fails over the default directory connection, check whether an alternate supported secure LDAP or existing ticket/hash authentication path applies.
- [ ] **14.3** If ESC1 is reported, verify subject-alternative-name control, client-authentication capability, enrollment rights, and approval requirements before requesting a certificate.
- [ ] **14.4** If ESC2 is reported, verify whether the template's application policy permits client authentication or can be chained through an enrollment-agent path.
- [ ] **14.5** If ESC3 is reported, check whether an enrollment-agent certificate can request a certificate on behalf of a higher-privileged account.
- [ ] **14.6** If ESC4 is reported, confirm the template ACL weakness, modify only the necessary template settings, exploit the resulting enrollment path, and restore the original configuration.
- [ ] **14.7** If ESC6 is reported, verify the CA-wide subject-alternative-name setting and use only an already-effective, in-scope configuration.
- [ ] **14.8** If ESC7 is reported, identify the specific CA management rights and determine whether a pending request or an authorized CA configuration path is applicable.
- [ ] **14.9** If ESC8 is reported, verify that web enrollment is available and that the permitted relay/coercion path is in scope before attempting it.
- [ ] **14.10** If ESC9 or ESC10 is reported, verify the template or certificate-mapping condition and whether the required account attribute can be changed and restored.
- [ ] **14.11** If ESC11 is reported, verify that the RPC enrollment endpoint meets the required security condition before following the documented relay path.
- [ ] **14.12** If ESC13 is reported, identify the issuance policy and linked privileged group before enrolling.
- [ ] **14.13** If ESC15 is reported, confirm the schema-version and application-policy conditions before requesting a certificate.
- [ ] **14.14** If Shadow Credentials are viable, use them as the documented certificate-adjacent path and remove the temporary key when appropriate.
- [ ] **14.15** If a certificate yields a hash or ticket, validate the resulting identity, test it against relevant services, and return to **07. Credentialed Enumeration** and **08. Attack-Path Review**.

## 15. Move laterally and escalate privileges on hosts

- [ ] **15.1** For each valid account, hash, or ticket, identify the hosts and services it can access and keep local and domain privileges distinct.
- [ ] **15.2** If an internal subnet is reachable only through a compromised host, check its interfaces and routes and establish an authorized pivot before scanning that segment.
- [ ] **15.3** On each newly compromised Windows host, inspect the current identity, group memberships, active sessions, and available privileges.
- [ ] **15.4** If local administrator or SYSTEM access is available, collect relevant SAM, LSA, cached-credential, and session-ticket material and analyze it for reusable domain credentials.
- [ ] **15.5** If SeBackupPrivilege is present, confirm it is usable; then follow the documented backup/shadow-copy route to collect NTDS and SYSTEM material, analyze it offline, and validate recovered hashes.
- [ ] **15.6** If SeBackupPrivilege is absent or unusable, stop that branch and return to the other credential, ACL, LAPS, GPO, and roasting paths.
- [ ] **15.7** If SeManageVolumePrivilege is present, assess the documented Windows-directory permission and DLL search-order path; verify the resulting identity before continuing.
- [ ] **15.8** If MSSQL is exposed, enumerate authentication and privilege context; only pursue command execution when the account and service configuration support it.
- [ ] **15.9** If you control an account with local administrator access on another host, examine that host for active domain sessions and additional credentials before moving on.
- [ ] **15.10** If a new password or hash is recovered, test it for reuse and return to **07. Credentialed Enumeration**.

## 16. Reach domain compromise

- [ ] **16.1** Check whether the current account has directory replication rights or an equivalent path to DCSync.
- [ ] **16.2** If replication rights are available, extract and preserve the relevant domain credential material; verify the resulting hashes and identities.
- [ ] **16.3** If you obtain Domain Admin-equivalent credentials or a DC-level identity, validate access to the domain controller and collect the required proof of domain compromise.
- [ ] **16.4** If SeBackupPrivilege allows access to NTDS material, confirm both the directory database and required system hive were collected successfully before offline analysis.
- [ ] **16.5** If a privileged certificate or ticket provides an alternative route to replication or DC access, verify the resulting privilege rather than assuming certificate enrollment alone proves compromise.
- [ ] **16.6** If GenericAll exists on a domain-controller computer object, try the documented Shadow Credentials route first; if PKINIT fails, evaluate the RBCD alternative.

## 17. Ticket-based options and post-exploitation

- [ ] **17.1** If a service-account or machine-account secret is recovered, record its domain SID, domain name, target host, and service principal before considering a Silver Ticket.
- [ ] **17.2** Use a Silver Ticket only for the service corresponding to the recovered account secret; prefer an available AES key, validate actual access, and do not assume injected group membership was accepted.
- [ ] **17.3** If the recovered secret belongs to a domain controller machine account, prioritize the documented replication path rather than treating it as an ordinary Silver Ticket credential.
- [ ] **17.4** If a krbtgt secret is recovered, distinguish the Golden Ticket path from the narrower Silver Ticket path and proceed only if persistence is in scope.
- [ ] **17.5** If a forged or delegated ticket fails, check time alignment, target service name, account existence, and whether PAC validation or delegation protections affect the path.
- [ ] **17.6** After ticket-based access, confirm the real privileges and service access obtained, then re-run **07. Credentialed Enumeration** and **08. Attack-Path Review**.
- [ ] **17.7** If you control the certificate authority server and its private key can be backed up, consider a Golden Certificate only as an in-scope post-compromise option.
- [ ] **17.8** Treat Golden Tickets, Silver Tickets, and Golden Certificates as post-compromise or persistence techniques; use them only when the exam scope requires them. ([Certificates](./Certificates.md), [Silver Ticket Attack](./Silver%20Ticket%20Attack.md))

## 18. Verify, clean up, and report

- [ ] **18.1** Verify every claimed foothold, privilege escalation, credential, and domain-compromise result with evidence from the target.
- [ ] **18.2** Preserve the enumeration finding that justified each exploitation step and document the source, target, result, and impact.
- [ ] **18.3** Restore temporary GPO/template changes, ACL grants, group memberships, SPNs, RBCD settings, shadow credentials, and other changes when appropriate and permitted.
- [ ] **18.4** Record any changes that cannot safely be reversed, including password resets, and explain their impact in the report.
- [ ] **18.5** Confirm that the final report clearly links each finding to its evidence, attack path, and demonstrated result.
