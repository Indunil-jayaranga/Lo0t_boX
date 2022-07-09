CONTENT
=======
* [RECON](#RECON)



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

