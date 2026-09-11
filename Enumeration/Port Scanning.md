# Export Target

```sh
export target=10.129.47.148
```

# Rustscan

```sh
rustscan -a $target --ulimit 10000 -- -Pn -n -sV -sC -oN nmap_output
```

# Nmap

```sh
nmap -Pn -sC -sV -n -p22,80 -T5 $target -oN nmap_result_
```