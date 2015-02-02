Sniffs passwords and hashes from an interface or pcap. Work in progress. Accurately sniffs:

* URLs visited
* HTTP site logins/passwords
* FTP logins/passwords
* IRC logins/passwords
* POP logins/passwords
* IMAP logins/passwords
* SMTP logins/passwords
* NTLM over HTTP challenge and response hashes

Adding in future:
* KERBEROS
* SNMP community string
* HTTP Basic Auth

Auto-detect the interface to sniff

```sudo python net-creds.py```


Choose eth0 as the interface

```sudo python net-creds.py -i eth0```


Read from pcap

```sudo python net-creds.py -p pcapfile```
