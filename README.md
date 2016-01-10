Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification. 

| Screenshots |
|:-----:|
| ![Screenie1](http://imgur.com/opQo7Bb.png) |
| ![Screenie2](http://imgur.com/Kl5I6Ju.png) |

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

Credit to [epocs](https://github.com/epocs):
```
sudo easy_install pip
sudo pip install scapy
sudo pip install pcapy
brew install libdnet --with-python
mkdir -p /Users/<username>/Library/Python/2.7/lib/python/site-packages
echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/<username>/Library/Python/2.7/lib/python/site-packages/homebrew.pth
sudo pip install pypcap
brew tap brona/iproute2mac
brew install iproute2mac
```
Then replace line 74 '/sbin/ip' with '/usr/local/bin/ip'.


####Importing net_creds as a Python module

net_creds can be imported and run within a Python script or larger project. To use net_creds as a module, first import it within your project file:

```python

	
	import net_creds
```

Then start it by making a call to net\_creds.run() as shown below:

```python
	
	import net_creds

	net_creds.run(interface='wlan0')

```

The net\_creds.run() function accepts the following keyword arguments:

- _interface_ - Choose an interface to listen on
- _pcap_ - Parse info from a pcap file; pcap='filename.pcap'
- _filterip_ - Do not sniff packets from this ip address

Note that net\_creds.run() is a blocking call, and that running net\_creds in parallel with other modules such as
sslstrip2 requires the use of daemon processes. For example:


```python

	import net_creds
	from multiprocessing import Process

	def run_net_creds(interface):

		net_creds.run(interface=interface)

	p = Process(target=net_creds.run, args=('wlan0',))
	p.start()

	print 'Run the rest of your code here'

	p.stop()

```

####Thanks
* Laurent Gaffie
* psychomario
