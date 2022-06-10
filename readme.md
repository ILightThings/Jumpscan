# Jumpscan

A quick golang port scanner that can be compiled and dropped onto a victim machine for a quick portscan. 



I needed the for an engagment that had multiple vlans and a very protective EDR. 

---
```
usage: Jumpscan [-h|--help] -p|--ports "<value>" -t|--target "<value>"
                [-T|--timeout <integer>]

                A quick, concurrent port scanner, that can be dropped onto a
                victem machine and ran.

Arguments:

  -h  --help     Print help information
  -p  --ports    TCP ports to scan. Single port, range, comma seperated
  -t  --target   IPv4 to target. Single, CIDR, comma seperated
  -T  --timeout  Timeout in seconds. Default: 0.5
```

Single Host, Port Range 
```
jumpscan.exe -t 192.168.100.86 -p 1-2048
```

CIDR Notation, comma seperated ports, timeout 1 second
```
jumpscan.exe -t 10.10.0.0/24 -p 22,80,135,139,443,445,3389 -T 1 
```

Comma Seperated Hosts, single port
```
jumpscan.exe -t 192.168.10.10, 172.162.50.50, 10.10.5.5 -p 22 
```


Output
```
jumpscan.exe -t 192.168.1.0/24 -p 22,443,80 

192.168.1.20
        Port 80 Open
        Port 22 Open
192.168.1.51
        Port 22 Open
192.168.1.10
        Port 80 Open
        Port 443 Open
192.168.1.197
        Port 22 Open
192.168.1.201
        Port 22 Open
192.168.1.230
        Port 80 Open
        Port 22 Open
192.168.1.244
        Port 22 Open
192.168.1.1
        Port 443 Open
        Port 80 Open
Scan Finished

```


## Warning
Avoid Large Amount of Ports + Large Number of ports.

Currently no rate limiting.
