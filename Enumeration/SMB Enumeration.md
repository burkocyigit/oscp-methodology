# Anonymous Login

## smbclient

```sh
smbclient -L //$target -N
```

### Get all files

```sh
smb: \> prompt OFF

smb: \> recurse ON

smb: \> mget *
```
### Guest

```sh
smbclient -L //$target -U "Guest"
```

# smbmap

```sh
smbmap -H $target
```