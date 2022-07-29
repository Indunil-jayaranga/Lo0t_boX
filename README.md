[README.md](https://github.com/Indunil-jayaranga/Lo0t_boX/files/9222608/README.md)
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
msf> use auxiliary/scanner/finger/finger_users

```


