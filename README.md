Sniffs passwords and hashes from an interface or pcap. 

###Sniffs

* URLs visited
* HTTP site logins/passwords
* HTTP Basic Auth
* FTP logins/passwords
* IRC logins/passwords
* POP logins/passwords
* IMAP logins/passwords
* SMTP logins/passwords
* SNMP community string
* NTLM challenge and response hashes
* Kerberos (untested, I have no pcaps)


###Examples

Auto-detect the interface to sniff

```sudo python net-creds.py```


Choose eth0 as the interface

```sudo python net-creds.py -i eth0```


Read from pcap

```sudo python net-creds.py -p pcapfile```
