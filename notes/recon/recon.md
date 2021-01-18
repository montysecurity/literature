# recon

## documenting things

```
mkdir dir; cd dir
asciinema rec vid.cast
# do work like normal
exit # to end recording
# take a break
cd dir
asciinema rec --append vid.cast
# continue working
```

- `dir` is a stand-in for any directory used as the working directory
- for playback, `asciinema play vid.cast` respects tmux while `cat vid.cast` does not
- asciinema link - https://asciinema.org/
- my preferred PS1 is below

```
PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\342\224\200[\$(date -u)\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
```

## hiding reconnaissance efforts
- refer to tactics covered in [pivoting](https://github.com/montyonsecurity/literature/blob/master/notes/pivoting/linux.md) or the [sshproxy](https://github.com/montyonsecurity/sshproxy) tool

- it is possible to identify OS's using only ping by checking ICMP TTLs, [here is the list](https://subinsb.com/default-device-ttl-values/)

## scanning
### fping & nmap (pretty fast)

`fping -a -g 192.168.86.0/24 2> /dev/null | xargs nmap -Pn`

### cleaning up -oN nmap output

`egrep --color=never "Nmap scan report for |open" allhosts_allports_sV_sC_vulns_verbose | grep -v ^\| | sed 's/Nmap scan report for //g' | tr -d '()'`

### stacking nmap

`nmap -p- -A -oN full.nmap 10.10.10.30 > /dev/null & nmap -v -r -T4 -A -oN initial.nmap 10.10.10.30`

## google dorking
- teamviewer registry keys (https://whynotsecurity.com/blog/teamviewer/)
`"SecurityPasswordAES" OR "OptionsPasswordAES" OR "SecurityPasswordExported" OR "PermanentPassword" filetype:reg`

## owasp zap-cli example
1. sudo zap-cli --zap-path /usr/share/zaproxy/zap.sh --verbose --api-key 12345 quick-scan --self-contained -l Low -o '-config api.key=12345' --spider --ajax-spider -r https://fqdn.target.domain/
2. sudo zap-cli -v --zap-path /usr/share/zaproxy/zap.sh start -o '-config api.key=12345
3. sudo zap-cli -v --api-key 12345 quick-scan --spider --ajax-spider --recursive --alert-level High -r http://fqdn.target.domain/
4. zap-cli --api-key 12345  report --output owasp.html --output-format html

My [pentest repo](https://github.com/montysecurity/pentest) contains a tool 

## metasploit framework console
- gobuster, dib-like - use auxiliary/scanner/http/dir\_scanner
- port scanners - db\_nmap, use auxiliary/scanner/portscan/

### meterpreter
- target box shadow file - run post/linux/gather/hashdump
- hydra (wordpress) - auxiliary/scanner/http/wordpress\_login\_enum

## nmap scripts
- defualt scripts - nmap -sC
- LDAP - nmap target - --script--ldap-search
- safe vuln enum - --scripts "safe and vuln"
- vuln enum - --scripts vuln
- all smb scripts (you can replace smb w/ ldap, ftp, etc.) - nmap -v -r -p 445 --script=$(locate \*smb\*.nse | awk -F'/' '{print $6}' | tr '\n' ',') -oN scripts\_smb.nmap target.ip

## wpscan example
wpscan --url http://target/wordpress/ -v --no-update --detection-mode aggressive --random-user-agent --disable-tls-checks --enumerate vp, vt, cb, dbe, u, m

if something fails to enumerate, re-run without it's flag because the program seems to exit at first failure. provide an api key (and have internet access) if you want it to do provide vulnernability details

## windows rpc bruteforce script
for i in $(cat users.txt); do for j in $(cat pass.txt); do echo $i%$j && rpcclient -U "$i%$j" 10.10.10.149 && sleep 1; done; done;

To get a proper shell, try the credentials with evil-winrm

## cisco router confguration files
some passwords in these files are XOR'd using "password 7", you can reverse using [this tool](https://github.com/theevilbit/ciscot7)

## crackmapexec
if you have valid creds, [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) is amazing for recon

	sudo apt install crackmapexec

## smbclient
Displaying shares

	smbclient -U '' -L vuln.hack

Accessing shares
	
	smbclient -U '' \\\\vuln.hack\\print$
