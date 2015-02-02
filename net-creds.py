#!/usr/bin/env python2

from os import geteuid, devnull
import logging
# Be quiet, you
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
from sys import exit
import binascii
import struct
import argparse
import signal
import base64
from urllib import unquote
from subprocess import Popen, PIPE
from collections import OrderedDict
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
#from IPython import embed

##################################################################################
# Left off:
# NTLM parsing is complete, but need way to track tcp sequence numbers so we can 
# keep track of chal:resp combos. I don't think adding them to pkt_frag dict works
# because that dict's keys are src_ip_port not tcp stream. Maybe new dict like 
# psychomario's ntlmparser? Don't forget to change the variable "challenge"
# within parse_resp_msg()
##################################################################################

DN = open(devnull, 'w')
pkt_frag_loads = OrderedDict()
challenge_acks = OrderedDict()
mail_auth = None

# Regexs
msg2_header_re = "(www-|proxy-)?authenticate"
msg3_header_re = "(www-|proxy-)?authorization"

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
        Number of chars in load < 100,000
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
            if len(ack) > 100000:
                # If load > 100,000 chars, just keep the last 200 chars
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
        seq = str(pkt[TCP].seq)
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
            if ftp_pass or ftp_user:
                return

            # Mail
            mail_msg_found = mail_logins(full_load, str_load, dst_ip_port, src_ip_port)
            if mail_msg_found == True:
                return

            # IRC
            irc_msg_found = irc_logins(str_load, src_ip_port, dst_ip_port)
            if irc_msg_found == True:
                return

        # HTTP
        http_parser(full_load, str_load, src_ip_port, ack, seq)

def mail_logins(full_load, str_load, src_ip_port, dst_ip_port):
    '''
    Catch IMAP, POP, and SMTP logins
    '''
    global mail_auth
    found = False

    # SMTP can use lots of different auth patterns, sometimes it passes the user
    # and password in one pkt, sometimes 2 pkts for ex.
    if mail_auth != None and src_ip_port == mail_auth:
        # SMTP auth was successful
        if '235' in str_load and 'auth' in str_load.lower():
            print '[%s] SMTP authentication successful' % dst_ip_port
            found = True
            mail_auth = None
        # SMTP failed
        elif str_load.startswith('535 '):
            print '[%s] SMTP authentication failed' % dst_ip_port
            found = True
            mail_auth = None
        # IMAP/POP/SMTP failed
        elif 'auth' in str_load.lower() and 'fail' in str_load.lower():
            print '[%s] mail authentication failed' % dst_ip_port
            found = True
            mail_auth = None
        # IMAP auth success
        elif ' OK [' in str_load:
            print '[%s] IMAP authentication successful' % dst_ip_port
            found = True
            mail_auth = None
        # IMAP auth failure
        elif ' NO ' in str_load and 'fail' in str_load.lower():
            print '[%s] IMAP authentication failed' % dst_ip_port
            found = True
            mail_auth = None

    # check if this packet is part of the auth packet tcp stream
    elif mail_auth == dst_ip_port:
        str_load = str_load.replace(r'\r\n', '')
        print '[%s > %s] mail auth: %s' % (src_ip_port, dst_ip_port, str_load)
        found = True
        try:
            decoded = base64.b64decode(str_load).replace('\x00', ' ')#[1:] # delete space at beginning
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
                found = True
                try:
                    decoded = base64.b64decode(smtp_auth).replace('\x00', ' ')#[1:] # delete space at beginning
                except Exception:
                    decoded = None
                if decoded != None:
                    print '[%s > %s] Decoded:' % (src_ip_port, dst_ip_port), decoded
                    found = True
            mail_auth = dst_ip_port

    if found == True:
        return True

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
    if irc_pass_re or irc_user_re:
        return True

def http_parser(full_load, str_load, src_ip_port, ack, seq):
    '''
    Pull out pertinent info from the parsed HTTP packet data
    '''
    user_passwd = None
    http_url_req = None
    host = None
    challenge = None
    response = None
    http_methods = ['GET ', 'POST ', 'CONNECT ', 'TRACE ', 'TRACK ', 'PUT ', 'DELETE ', 'HEAD '] 
    http_line, header_lines, body = parse_http_load(full_load)
    headers = headers_to_dict(header_lines)
    method, path = parse_http_line(http_line, http_methods)
    http_url_req = get_http_url(method, path, headers)

    if body != '':
        user_passwd = get_login_pass(body)

    if len(headers) == 0:
        ntlm_chal_header = None
        ntlm_resp_header = None
    for header in headers:
        ntlm_chal_header = re.search(msg2_header_re, header)
        ntlm_resp_header = re.search(msg3_header_re, header)
        if ntlm_chal_header or ntlm_resp_header:
            break

    # Type 2 challenge from server
    if ntlm_chal_header != None:
        chal_header = ntlm_chal_header.group()
        challenge = parse_chal_msg(headers, chal_header, ack)

    # Type 3 response from client
    elif ntlm_resp_header != None:
        resp_header = ntlm_resp_header.group()
        hash_type, crackable_hash = parse_resp_msg(headers, resp_header, seq)
        if hash_type and crackable_hash:
            print  '  ', hash_type, crackable_hash

    ############ PRINT STUFF ###############
    if user_passwd != None:
        print '  User:', user_passwd[0]
        print '  Pass:', user_passwd[1]
    if http_url_req:
        print http_url_req

def get_http_url(method, path, headers):
    '''
    Get the HTTP method + URL from requests
    '''
    if method != None and path != None:

        if 'host' in headers:
            host = headers['host']
        else:
            host = ''

        # Make sure the path doesn't repeat the host header
        if host != '' and not re.match('(http(s)?://)?'+host, path):
            http_url_req = method + ' ' + host + path
        else:
            http_url_req = method + ' ' + path

        http_url_req = url_filter(http_url_req)

        return http_url_req

def headers_to_dict(header_lines):
    '''
    Convert the list of header lines into a dictionary
    '''
    headers = {}
    # Incomprehensible list comprehension flattens list of headers
    # that are each split at ': '
    # http://stackoverflow.com/a/406296
    headers_list = [x for line in header_lines for x in line.split(': ', 1)]
    headers_dict = dict(zip(headers_list[0::2], headers_list[1::2]))
    # Make the header key (like "Content-Length") lowercase
    for header in headers_dict:
        headers[header.lower()] = headers_dict[header]

    return headers

def parse_http_line(http_line, http_methods):
    '''
    Parse the header with the HTTP method in it
    '''
    http_line_split = http_line.split()
    method = ''
    path = ''

    # Accounts for pcap files that might start with a fragment
    # so the first line might be just text data
    if len(http_line_split) > 1:
        method = http_line_split[0]
        path = http_line_split[1]

    # This check exists because responses are much different than requests e.g.:
    #     HTTP/1.1 407 Proxy Authentication Required ( Access is denied.  )
    # Add a space to method because there's a space in http_methods items
    # to avoid false+
    if method+' ' not in http_methods:
        method = None
        path = None

    return method, path

def parse_http_load(full_load):
    '''
    Split the raw load into list of headers and body string
    '''
    try:
        headers, body = full_load.split("\r\n\r\n", 1)
    except ValueError:
        headers = full_load
        body = ''
    except:
        raise
    header_lines = headers.split("\r\n")
    http_line = header_lines[0]
    header_lines = [line for line in header_lines if line != http_line]

    return http_line, header_lines, body

def get_http_line(header_lines, http_methods):
    '''
    Get the header with the http command
    '''
    for header in header_lines:
        for method in http_methods:
            if method in header:
                http_line = header
                return http_line

def parse_chal_msg(headers, chal_header, ack):
    '''
    Parse the server challenge
    https://code.google.com/p/python-ntlm/source/browse/trunk/python26/ntlm/ntlm.py
    '''
    global challenge_acks

    header_val2 = headers[chal_header]
    header_val2 = header_val2.split(' ', 1)
    # The header value can either start with NTLM or Negotiate
    if header_val2[0] == 'NTLM' or header_val2[0] == 'Negotiate':
        msg2 = header_val2[1]
        msg2 = base64.decodestring(msg2)
        Signature = msg2[0:8]
        msg_type = struct.unpack("<I",msg2[8:12])[0]
        assert(msg_type==2)
        ServerChallenge = msg2[24:32].encode('hex')

        # Keep the dict of ack:challenge to less than 50 chals
        if len(challenge_acks) > 50:
            challenge_acks.popitem(last=False)
        challenge_acks[ack] = ServerChallenge

        return ServerChallenge

def parse_resp_msg(headers, resp_header, seq):
    '''
    Parse the client response to the challenge
    '''

    if seq in challenge_acks:
        challenge = challenge_acks[seq]
    else:
        challenge = 'CHALLENGE NOT FOUND'

    header_val3 = headers[resp_header]
    header_val3 = header_val3.split(' ', 1)
    # The header value can either start with NTLM or Negotiate
    if header_val3[0] == 'NTLM' or header_val3[0] == 'Negotiate':
        msg3 = base64.decodestring(header_val3[1])
        # What is this when it's not > 43? Is it msg1?
        if len(msg3) > 43:
            # Thx to psychomario for below
            lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack("12xhhihhihhihhi", msg3[:44])
            lmhash = binascii.b2a_hex(msg3[lmoff:lmoff+lmlen])
            nthash = binascii.b2a_hex(msg3[ntoff:ntoff+ntlen])
            domain = msg3[domoff:domoff+domlen].replace("\0", "")
            user = msg3[useroff:useroff+userlen].replace("\0", "")
            if lmhash != "0"*48: #NTLM
                return "NETNTLMv1", user+"::"+domain+":"+lmhash+":"+nthash+":"+challenge
            else: #NTLMv2
                return "NETNTLMv2", user+"::"+domain+":"+challenge+":"+nthash[:32]+":"+nthash[32:]
    return None, None

def url_filter(http_url_req):
    '''
    Filter out the common but uninteresting URLs
    '''
    if http_url_req:
        d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
        if any(http_url_req.endswith(i) for i in d):
            return

    return http_url_req

def get_login_pass(body):
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
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfield in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
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
        decoded = base64.b64decode(load)#.replace('\x00', ' ')#[1:] # delete space at beginning
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

    # Read packets from either pcap or interface
    if args.pcap:
        try:
            pcap = rdpcap(args.pcap)
        except Exception:
            exit('[-] Could not open %s' % args.pcap)
        for pkt in pcap:
            pkt_parser(pkt)
    else:
        # Check for root
        if geteuid():
            exit('[-] Please run as root')

        #Find the active interface
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = iface_finder()
        print '[*] Using interface:', conf.iface

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
            #        decoded = base64.b64decode(b64.group()).replace('\x00', ' ')#[1:] # delete space at beginning
            #    except Exception:
            #        decoded = None
            #    if decoded != None:
            #        print '[%s > %s] Decoded:' % (src_ip_port, dst_ip_port), decoded

