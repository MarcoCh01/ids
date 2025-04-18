VLAN 100 (PROD_S1 - PROD_S8):
* `alert ip !10.0.100.0/24 any -> 10.0.100.0/24 any (msg:"Traffic to management VLAN 100 from outside"; sid:1100001; rev:1;)`

* `alert ip ![10.0.100.0/24, 10.0.90.0/24] any -> 10.0.100.0/24 any (msg:"Traffic to management VLAN 100 (from outside VLAN 100 & 90)"; sid:1100001; rev:1;)`

* `alert ip 10.0.220.0/24 any -> 10.0.100.0/24 any (msg:"Traffic to management VLAN 100 from VLAN 220 (users)"; sid:1100002; rev:1;)`

--

Basic testing rules

* `alert icmp any any -> 8.8.8.8 any (msg:"ICMP Ping 8.8.8.8"; itype:8; sid:1000001; rev:1;)`
  * Príklad: `ping 8.8.8.8`

* `alert tcp any any -> any 22 (msg:"SSH / port 22 traffic"; sid:1000002; rev:1;)`
  * Príklad: `ssh <target>`

* `alert ip any any -> any any (msg:"Rule for testmyids.com"; content:"uid=0(root)"; sid:1000003; rev:1;)`
  * Príklad: `curl testmyids.com`

--

* `alert tcp any any -> any any (msg:"Possible TCP SYN Flood DoS Attack"; flags: S; threshold: type both, track by_src, count 100, seconds 1; sid:1000111; rev:1;)`
  * Príklad: `hping3 -S --flood -p <port> <target_ip>`

* `alert udp any any -> any any (msg:"Possible UDP Flood DoS Attack"; threshold: type both, track by_src, count 100, seconds 1; sid:1000112; rev:1;)`
  * Príklad: `hping3 --udp --flood -p <port> <target_ip>`

* `alert icmp any any -> any any (msg:"Possible ICMP Flood DoS Attack"; itype:8; threshold: type both, track by_dst, count 200, seconds 1; sid:1000113; rev:1;)`
  * Príklad: `hping3 --icmp --flood -c 1000 --spoof <spoofed_src_ip> <target_ip>`
  * Príklad: `hping3 <target_ip> --flood --rand-source --icmp -c 1000`
  

// classtype:attempted-dos;

--

* `alert tcp any any -> any any (msg:"Potential Nmap SYN Scan"; flags:S; threshold:type threshold, track by_src, count 10, seconds 3; sid:1000012; rev:1;)`
  * Príklad: `nmap -sS -p 1-1000 <target_ip>`
  
* `alert tcp any any -> any 22 (msg:"SSH Brute Force"; flow:to_server,established; content:"SSH-2.0"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000013; rev:1;)`
  * Príklad: `hydra -l root -P /path/to/wordlist.txt ssh://<target-ip>`

--

* `alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 64; content:"ECHO REQUEST"; sid:1000014;)`
* `alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 128; content:"ECHO REPLY"; sid:1000015;)`
  * Príklad: `sudo nmap -O <target_ip>`

--

* `alert http any any -> any any (msg:"Cross-Site Scripting (XSS)"; flow:established,to_server; content:"<script>"; nocase; http_uri; classtype:web-application-attack; sid:1000021;)`

* `alert http any any -> any any (msg:"SQL Injection"; flow:established,to_server; content:"SELECT"; nocase; http_uri; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; classtype:web-application-attack; sid:1000031;)`

* `alert http any any -> any any (msg:"Command Injection Attempt"; content:"/bin/bash"; sid:1000041;)`


* Netbox - pravidlo na pokus o pristup z User PC do administracie switchov/routrov ?
