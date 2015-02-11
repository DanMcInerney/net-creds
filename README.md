Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.

###Sniffs

* URLs visited
* POST loads sent
* HTTP site logins/passwords
* HTTP basic auth
* HTTP searches
* FTP logins/passwords
* IRC logins/passwords
* POP logins/passwords
* IMAP logins/passwords
* SMTP logins/passwords
* SNMP community string
* NETNTLM challenge and response hashes
* Kerberos (untested, I have no pcaps)


###Examples

Auto-detect the interface to sniff

```sudo python net-creds.py```


Choose eth0 as the interface

```sudo python net-creds.py -i eth0```


Read from pcap

```sudo python net-creds.py -p pcapfile```


####Thanks
* Laurent Gaffie writer of PCredz
* psychomario writer of ntlmsspparser

