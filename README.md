Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification. Screenshots: http://imgur.com/opQo7Bb http://imgur.com/Kl5I6Ju

###Sniffs

* URLs visited
* POST loads sent
* HTTP form logins/passwords
* HTTP basic auth logins/passwords
* HTTP searches
* FTP logins/passwords
* IRC logins/passwords
* POP logins/passwords
* IMAP logins/passwords
* Telnet logins/passwords
* SMTP logins/passwords
* SNMP community string
* NTLMv1/v2 all supported protocols like HTTP, SMB, LDAP, etc
* Kerberos


###Examples

Auto-detect the interface to sniff

```sudo python net-creds.py```

Choose eth0 as the interface

```sudo python net-creds.py -i eth0```

Ignore packets to and from 192.168.0.2

```sudo python net-creds.py -f 192.168.0.2```

Read from pcap

```python net-creds.py -p pcapfile```


####OSX

I haven't tested this on OSX but I suspect you should be able to get it to run. Install scapy:

http://www.secdev.org/projects/scapy/portability.html#osx

Install iproute2mac and change all references in net-creds from "/sbin/ip" to "/usr/local/bin/ip"

```brew tap brona/iproute2mac brew install iproute2mac```


####Thanks
* Laurent Gaffie
* psychomario
