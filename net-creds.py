#!/usr/bin/env python2

from os import geteuid, devnull
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
from sys import exit
import argparse
import signal
from base64 import b64decode
from urllib import unquote
from subprocess import Popen, PIPE
from collections import OrderedDict
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
#from IPython import embed

DN = open(devnull, 'w')
pkt_frag_loads = OrderedDict()
mail_auth = None

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   parser.add_argument("-f", "--filterip", help="Do not sniff packets from this IP address; -f 192.168.0.4")
   return parser.parse_args()

def iface_finder():
    try:
        ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        for line in ipr.communicate()[0].splitlines():
            if 'default' in line:
                l = line.split()
                iface = l[4]
                return iface
    except Exception:
        exit('[-] Could not find an internet active interface; please specify one with -i <interface>')

def frag_remover(ack, load):
    '''
    Keep the FILO OrderedDict of frag loads from getting too large
    3 points of limit:
        Number of ip_ports < 50
        Number of acks per ip:port < 25
        Number of chars in load < 75,000
    '''
    global pkt_frag_loads

    # Keep the number of IP:port mappings below 50
    # last=False pops the oldest item rather than the latest
    while len(pkt_frag_loads) > 50:
        pkt_frag_loads.popitem(last=False)

    # Loop through a deep copy dict but modify the original dict
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        if len(copy_pkt_frag_loads[ip_port]) > 0:
            # Keep 25 ack:load's per ip:port
            while len(copy_pkt_frag_loads[ip_port]) > 25:
                pkt_frag_loads[ip_port].popitem(last=False)

    # Recopy the new dict to prevent KeyErrors for modifying dict in loop
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        # Keep the load less than 75,000 chars
        for ack in copy_pkt_frag_loads[ip_port]:
            if len(ack) > 75000:
                # If load > 75,000 chars, just keep the last 200 chars
                pkt_frag_loads[ip_port][ack] = pkt_frag_loads[ip_port][ack][-200:]

def frag_joiner(ack, src_ip_port, load):
    '''
    Keep a store of previous fragments in an OrderedDict named pkt_frag_loads
    '''
    for ip_port in pkt_frag_loads:
        if src_ip_port == ip_port:
            if ack in pkt_frag_loads[src_ip_port]:
                # Make pkt_frag_loads[src_ip_port][ack] = full load
                old_load = pkt_frag_loads[src_ip_port][ack]
                concat_load = old_load + load
                return OrderedDict([(ack, concat_load)])

    return OrderedDict([(ack, load)])

def pkt_parser(pkt):
    '''
    Start parsing packets here
    '''
    global pkt_frag_loads, mail_auth

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP):
        return

    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
        #print pkt.summary()
        ack = str(pkt[TCP].ack)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
        load = pkt[Raw].load
        frag_remover(ack, load)
        pkt_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
        full_load = pkt_frag_loads[src_ip_port][ack]
        # doing str(load) throws nonASCII character output
        # [1:-1] just gets eliminates the single quotes at start and end
        str_load = repr(full_load)[1:-1]

        # Limit the packets we regex to increase efficiency
        # 750 is a but arbitrary but some SMTP auth success pkts
        # are 500+ characters
        if 1 < len(str_load) < 750:

            # FTP
            ftp_user = re.match(r'USER (.+)\\r\\n', str_load)
            ftp_pass = re.match(r'PASS (.+)\\r\\n', str_load)
            if ftp_user:
                print '  FTP User: ', ftp_user.group(1).strip()
            if ftp_pass:
                print '  FTP Pass: ', ftp_pass.group(1).strip()

            # Mail
            mail_logins(full_load, str_load, dst_ip_port, src_ip_port)

            # IRC
            irc_logins(str_load, src_ip_port, dst_ip_port)

        # HTTP
        http_parser(full_load, str_load)

def mail_logins(full_load, str_load, src_ip_port, dst_ip_port):
    '''
    Catch IMAP, POP, and SMTP logins
    '''
    global mail_auth

    # SMTP can use lots of different auth patterns, sometimes it passes the user
    # and password in one pkt, sometimes 2 pkts for ex.
    if mail_auth != None and src_ip_port == mail_auth:
        # SMTP auth was successful
        if '235' in str_load and 'auth' in str_load.lower():
            print '[%s] SMTP authentication successful' % dst_ip_port
            mail_auth = None
        # SMTP failed
        elif str_load.startswith('535 '):
            print '[%s] SMTP authentication failed' % dst_ip_port
            mail_auth = None
        # IMAP/POP/SMTP failed
        elif 'auth' in str_load.lower() and 'fail' in str_load.lower():
            print '[%s] mail authentication failed' % dst_ip_port
            mail_auth = None
        # IMAP auth success
        elif ' OK [' in str_load:
            print '[%s] IMAP authentication successful' % dst_ip_port
            mail_auth = None
        # IMAP auth failure
        elif ' NO ' in str_load and 'fail' in str_load.lower():
            print '[%s] IMAP authentication failed' % dst_ip_port
            mail_auth = None

    # check if this packet is part of the auth packet tcp stream
    elif mail_auth == dst_ip_port:
        str_load = str_load.replace(r'\r\n', '')
        print '[%s > %s] mail auth: %s' % (src_ip_port, dst_ip_port, str_load)
        try:
            decoded = b64decode(str_load).replace('\x00', ' ')#[1:] # delete space at beginning
        except Exception:
            decoded = None
        if decoded != None:
            print '[%s > %s] Decoded:' % (src_ip_port, dst_ip_port), decoded
    else:
        mail_auth_re = re.search('auth login|auth plain|authenticate plain', str_load.lower())
        # SMTP sends packets like '250- auth plain' sometimes that we must filter
        if mail_auth_re and not str_load.startswith('250'):
            smtp_line = str_load.split(' ')
            # check if this is a single line auth like AUTH PLAIN XcvxSVSD24SADFDF==
            if len(smtp_line) == 3 and smtp_line[2].lower().replace(r'\r\n', '') not in ['plain', 'login']:
                smtp_auth = smtp_line[2]
                print '[%s > %s] SMTP auth: %s' % (src_ip_port, dst_ip_port, smtp_auth)
                try:
                    decoded = b64decode(smtp_auth).replace('\x00', ' ')#[1:] # delete space at beginning
                except Exception:
                    decoded = None
                if decoded != None:
                    print '[%s > %s] Decoded:' % (src_ip_port, dst_ip_port), decoded
            mail_auth = dst_ip_port

def irc_logins(str_load, src_ip_port, dst_ip_port):
    '''
    Find IRC logins
    '''
    irc_user_re = re.match(r'NICK (.+?)(\\r\\n| )', str_load)
    irc_pass_re = re.match(r'NS IDENTIFY (.+?)(\\r\\n| )', str_load)
    if irc_user_re:
        print '[%s > %s] IRC nick: ' % (src_ip_port, dst_ip_port), irc_user_re.group(1).strip()
    if irc_pass_re:
        print '[%s > %s] IRC pass: ' % (src_ip_port, dst_ip_port), irc_user_re.group(1).strip()

class HTTPRequest(BaseHTTPRequestHandler):
    '''
    Parse out the HTTP headers and body
    '''
    def __init__(self, full_load):
        self.rfile = StringIO(full_load)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

def http_parser(full_load, str_load):
    '''
    Pull out pertinent info from the parsed HTTP packet data
    '''
    user_passwd = None
    auth_header = None
    http_ntlm = None
    request = HTTPRequest(full_load)

    if request.error_code == None: # What about 401 headers like NTLM over HTTP uses?
        try:
            cmd = request.command
            path = request.path
            host = request.headers['host']
            data = str_load.split(r'\r\n\r\n', 1)
            if len(data) > 1 and type(data) == list:
                data = data[1]
            cmd_url = cmd + ' ' + host + path
            url_printer(cmd_url)

            if data != '':
                user_passwd = get_login_pass(data)
                print ' ',data[:175]

            # Grab authorization headers s for server c for client
            if 'authorization' in request.headers:# or 'proxy-authorization' in request.headers:
                if 'NTLM ' in request.headers['authorization']:
                    c_ntlm_b64 = request.headers['authorization'].replace('NTLM ', '')
                    try:
                        decoded_c_ntlm = b64decode(c_ntlm_b64)
                        print 'DECODED:', decoded_c_ntlm
                        # Third pkt from client in 3 way handshake
                        ntlm3_re = re.search('NTLMSSP\x00\x03\x00\x00\x00(.+)', decoded_c_ntlm, re.DOTALL)
                        if ntlm3_re:
                            print ntlm3_re.group(1)
                        print 'USERNAME:', decoded_c_ntlm[60:64].encode('hex')
                    except Exception as e:
                        print '\n' + str(e)

                   # # First pkt from client in 3 way handshake
                   # ntlm1_re = re.search('NTLMSSP\x00\x01\x00\x00\x00(.+)', decoded_c_ntlm)
                   # if ntlm1_re:
                   #     print repr(ntlm1_re.group(1))
                   #     print repr(decoded_c_ntlm)


            if 'www-authenticate' in request.headers:
                if 'NTLM ' in request.headers['www-authenticate']:
                    s_ntlm_b64 = request.headers['www-authenticate'].replace('NTLM ', '')
                    decoded_s_ntlm = b64decode(c_ntlm_b64)
                    ntlm2_re = re.search('NTLMSSP\x00\x02\x00\x00\x00(.+)', decoded_s_ntlm, re.DOTALL)

                    #print decoded_s_ntlm.encode('hex')

        ################## DEBUG ########################
        except Exception as e:
            print ' ****************** ERROR'
            print str(e)
            print str_load[:100]
        ################## DEBUG ########################

    if user_passwd != None:
        print '  User:', user_passwd[0]
        print '  Pass:', user_passwd[1]
    if auth_header != None:
        print ' ',auth_header

def url_printer(cmd_url):
    '''
    Filter out the common but uninteresting URLs
    '''
    d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
    if any(cmd_url.endswith(i) for i in d):
        return

    print ' ',cmd_url[:175]

def get_login_pass(data):
    '''
    Regex out logins and passwords from a string
    '''
    user = None
    passwd = None

    # Taken mainly from Pcredz by Laurent Gaffie
    userfields = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd']

    for login in userfields:
        login_re = re.search('(%s=[^&]+)' % login, data, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfield in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfield, data, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group()

    if user and passwd:
        return (user, passwd)

def decode64(str_load):
    '''
    Decode base64 strings
    '''
    #remove \r\n\r\n
    load = str_load.replace(r'\r\n', '')
    try:
        decoded = b64decode(load)#.replace('\x00', ' ')#[1:] # delete space at beginning
    except Exception as e:
        print str(e)
        decoded = None
    if decoded != None:
        print '    Decoded: %s' % decoded

def main(args):

    ############################### DEBUG ###############
    # Hit Ctrl-C while program is running and you can see
    # whatever variable you want within the IPython cli
    #def signal_handler(signal, frame):
    #    embed()
    ##    sniff(iface=conf.iface, prn=pkt_parser, store=0)
    #signal.signal(signal.SIGINT, signal_handler)
    #####################################################

    # Check for root
    if geteuid():
        exit('[-] Please run as root')

    #Find the active interface
    if args.interface:
        conf.iface = args.interface
    else:
        conf.iface = iface_finder()

    # Read packets from either pcap or interface
    if args.pcap:
        try:
            pcap = rdpcap(args.pcap)
        except Exception:
            exit('[-] Could not open %s' % args.pcap)
        for pkt in pcap:
            pkt_parser(pkt)
    else:
        if args.filterip:
            sniff(iface=conf.iface, prn=pkt_parser, filter="not host %s" % args.filterip, store=0)
        else:
            sniff(iface=conf.iface, prn=pkt_parser, store=0)


if __name__ == "__main__":
   main(parse_args())


            # Check for successful authentication
            #b64_re = "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            #b64_re = r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)'
            #b64 = re.search(b64_re, str_load)
            #if b64 != None:
            #    print b64.group()
            #    try:
            #        decoded = b64decode(b64.group()).replace('\x00', ' ')#[1:] # delete space at beginning
            #    except Exception:
            #        decoded = None
            #    if decoded != None:
            #        print '[%s > %s] Decoded:' % (src_ip_port, dst_ip_port), decoded

