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
    Keep the OrderedDict of frag loads from getting too large
    3 points of limit: number of IP:port keys, number of different acks, and len of ack
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
    global pkt_frag_loads

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP):
        return

    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
        print pkt.summary()

        ack = str(pkt[TCP].ack)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].sport)
        load = pkt[Raw].load
        frag_remover(ack, load)
        pkt_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
        full_load = pkt_frag_loads[src_ip_port][ack]
        # doing str(load) throws nonASCII character output
        # [1:-1] just gets eliminates the single quotes at start and end
        str_load = repr(full_load)[1:-1]

        # Limit the packets we regex to increase efficiency
        if len(str_load) < 150:
            # FTP
            ftp_user = re.match(r'USER (.*)\\r\\n', str_load)
            ftp_pass = re.match(r'PASS (.*)\\r\\n', str_load)
            if ftp_user:
                print '  FTP User: ', ftp_user.group(1)
            if ftp_pass:
                print '  FTP Pass: ', ftp_pass.group(1)

            # IRC
            irc_user_re = re.match(r'NICK (\w)', str_load)
            irc_pass_re = re.match(r'NS IDENTIFY (\w)', str_load)
            if irc_user_re:
                print '  IRC nick: ', irc_user_re.group(1)
            if irc_pass_re:
                print '  IRC pass: ', irc_user_re.group(1)

        # HTTP
        http_parser(full_load, str_load)

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
            data = str_load.split(r'\r\n\r\n', 1)[1]
            cmd_url = cmd + ' ' + host + path
            url_printer(cmd_url)

            if data != '':
                user_passwd = get_login_pass(data)
                print ' ',data[:175]
            # Grab authorization headers
            if 'authorization' in request.headers:
                auth_header = request.headers['authorization']
                if ' NTLM' in auth_header:
                    ntlm_hash = auth_header.strip(' NTLM ')

                # Get NTLM over HTTP
                #if ' NTLM' in auth_header:

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
            pcap = rdpcap(pcap_file)
        except Exception:
            exit('[-] Could not open %s' % pcap_file)
        for pkt in pcap:
            pkt_parser(pkt)
    else:
        sniff(iface=conf.iface, prn=pkt_parser, filter="not host %s" % args.filterip, store=0)


if __name__ == "__main__":
   main(parse_args())
