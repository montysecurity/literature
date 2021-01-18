# windows privesc

## tools

- [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
- [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
- [bloodhound](https://github.com/BloodHoundAD/BloodHound)
- [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

## powershell script execution policy

sometimes ps will not let you run ps scripts as a part of an execution policy, two possible ways around this would be piping the contents of the script to powershell.exe or just pasting it in a ps prompt

## procdump

dump process memory

upload to target then...

	./procdump -ma [Process ID]

You can find the PID using *ps* (it is the column immediately left of the process name

## batch scripts

`gci -file -force -r . \*.bat`
