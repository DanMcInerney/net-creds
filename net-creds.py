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
from IPython import embed

##################################################################################
# Left off:
# Do kerberos
# Fix mail auths so they're not using 1 global var, what if there's multiple
# connections? Just track the auth and password packets via seq and ack
# migiht be handling fragments wrong, what if the pcap starts with a fragment
# how does it handle headers then? seems like it just assumes the fragment is a header
##################################################################################

DN = open(devnull, 'w')
pkt_frag_loads = OrderedDict()
challenge_acks = OrderedDict()
mail_auths = OrderedDict()

# Regexs
authenticate_re = '(www-|proxy-)?authenticate'
authorization_re = '(www-|proxy-)?authorization'
ftp_user_re = r'USER (.+)\\r\\n'
ftp_pw_re = r'PASS (.+)\\r\\n'
irc_user_re = r'NICK (.+?)(\\r\\n| )'
irc_pw_re = r'NS IDENTIFY (.+?)(\\r\\n| )'
mail_auth_re = '(\d+ )?(auth|authenticate) (login|plain)'
mail_auth_re1 =  '(\d+ )?login '

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
        raise
        exit('[-] Could not find an internet active interface; please specify one with -i <interface>')

def frag_remover(ack, load):
    '''
    Keep the FILO OrderedDict of frag loads from getting too large
    3 points of limit:
        Number of ip_ports < 50
        Number of acks per ip:port < 25
        Number of chars in load < 5000
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
            # If load > 5000 chars, just keep the last 200 chars
            if len(copy_pkt_frag_loads[ip_port][ack]) > 5000:
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
    global pkt_frag_loads, mail_auths


    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return

    if pkt.haslayer(UDP):

        # SNMP community strings
        if pkt.haslayer(SNMP):
            parse_snmp(pkt[SNMP])
            return

        #Kerberos over UDP here
        ######################

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

            # Mail
            mail_creds_found = mail_logins(full_load, src_ip_port, dst_ip_port, ack, seq)
            if mail_creds_found:
                return

            # FTP
            # FTP USER: xxx PASS: xxx format is copied in some POP implementations
            ftp_pkt_found = parse_ftp(str_load, dst_ip_port, src_ip_port)
            if ftp_pkt_found == True:
                return

            # IRC
            irc_creds = irc_logins(str_load, src_ip_port, dst_ip_port)
            if irc_creds != None:
                printer(src_ip_port, dst_ip_port, irc_creds)
                return

        # HTTP and other protocols that run on TCP + a raw load
        other_parser(full_load, str_load, src_ip_port, ack, seq)

def parse_ftp(str_load, src_ip_port, dst_ip_port):
    '''
    Parse out FTP creds
    '''
    ftp_user = re.match(ftp_user_re, str_load)
    ftp_pass = re.match(ftp_pw_re, str_load)
    if ftp_user:
        print '[%s]>[%s]   FTP User:' % (src_ip_port, dst_ip_port), ftp_user.group(1).strip()
        return True
    if ftp_pass:
        print '[%s]>[%s]   FTP Pass:' % (src_ip_port, dst_ip_port), ftp_pass.group(1).strip()
        return True

def mail_decode(src_ip_port, dst_ip_port, mail_creds):
    '''
    Decode base64 mail creds
    '''
    try:
        decoded = base64.b64decode(mail_creds).replace('\x00', ' ').encode('utf8')
        decoded = decoded.replace('\x00', ' ')
    except TypeError:
        decoded = None
    except UnicodeDecodeError:
        decoded = None

    if decoded != None:
        msg = '    Decoded: %s' % decoded
        printer(src_ip_port, dst_ip_port, msg)

def mail_logins(full_load, src_ip_port, dst_ip_port, ack, seq):
    '''
    Catch IMAP, POP, and SMTP logins
    '''
    # Handle the first packet of mail authentication
    # if the creds aren't in the first packet, save it in mail_auths

    # Note that some printer() functions reverse the src and dst
    # so as not to confuse since auth successful pkts necessarily
    # come from the server and we don't want it to look like the
    # server authenticated to the client

    # LEFT OFF:
    # How to organize this? Check if the dst server is stored already then do else: look for authorization pkt?
    # Problem is that multiple failed attempts are all in the same tcp stream. How to reset consistently 
    # if auth failure?

    # mail_auths = 192.168.0.2:[first ack, ]
    global mail_auths
    found = False

    # Sometimes mail packets double up on the authentication lines
    # We just want the lastest one. Ex: "1 auth plain\r\n2 auth plain\r\n"
    num = full_load.count('auth')
    if num > 1:
        lines = full_load.count('\r\n')
        if lines > 1:
            full_load = full_load.split('\r\n')[-1]

    # Server responses to client
    # seq always = last ack of tcp stream
    if dst_ip_port in mail_auths:
        if seq in mail_auths[dst_ip_port][-1]:
            # look for any kind of auth failure or success
            a_s = '   Mail authentication successful'
            a_f = '   Mail authentication failed'
            # SMTP auth was successful
            if full_load.startswith('235') and 'auth' in full_load.lower():
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_s)
                found = True
                del mail_auths[dst_ip_port]
            # SMTP failed
            elif full_load.startswith('535 '):
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_f)
                found = True
                del mail_auths[dst_ip_port]
            # IMAP/POP/SMTP failed
            elif 'fail' in full_load.lower():
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_f)
                found = True
                del mail_auths[dst_ip_port]
            # IMAP auth success
            elif ' OK [' in full_load:
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_s)
                found = True
                del mail_auths[dst_ip_port]

           # Just a regular server > client acknowledgement pkt
           else:
                # Keep the dictionary less than 100
                if len(mail_auths) > 100:
                    mail_auths.popitem(last=False)
                mail_auths[src_ip_port] = [ack]

    # Client to server
    elif src_ip_port in mail_auths:
        if seq in mail_auths[src_ip_port][-1]:
            ##### LOOK FOR CREDS HERE

        # Client to server but it's a new TCP seq
        # This handles most POP/IMAP/SMTP logins but there's at least one edge case
        else:
            mail_auth_search = re.match(mail_auth_re, full_load, re.IGNORECASE)
            if mail_auth_search != None:
                auth_msg = full_load
                # IMAP uses the number at the beginning
                if mail_auth_search.group(1) != None:
                    auth_msg = auth_msg.split()[1:]
                else:
                    auth_msg = auth_msg.split()
                # Check if its a pkt like AUTH PLAIN dvcmQxIQ==
                # rather than just an AUTH PLAIN
                if len(auth_msg) > 2:
                    mail_creds = ' '.join(auth_msg[2:])
                    msg = '    Mail authentication: %s' % mail_creds
                    printer(src_ip_port, dst_ip_port, msg)
                    mail_decode(src_ip_port, dst_ip_port, mail_creds)
                    del mail_auths[src_ip_port]
                    found = True

            # At least 1 mail login style doesn't fit in the original regex
            # 1 login "username" "password"
            else:
                edge_case1 = re.match(mail_auth_re1, full_load, re.IGNORECASE)
                if edge_case1 != None:
                    auth_msg = full_load
                    auth_msg = auth_msg.split()
                    if 2 < len(auth_msg) < 5:
                        mail_creds = ' '.join(auth_msg[2:])
                        msg = '    Mail authentication: %s' % mail_creds
                        printer(src_ip_port, dst_ip_port, msg)
                        mail_decode(src_ip_port, dst_ip_port, mail_creds)
                        found = True

            # Pkt was just the initial auth cmd, next pkt from client will hold creds
            else:
                # Keep the dictionary less than 100
                if len(mail_auths) > 100:
                    mail_auths.popitem(last=False)
                mail_auths[src_ip_port] = [ack]


    # 2nd+ client auth pkts
    elif src_ip_port in mail_auths:
        if seq == mail_auths[src_ip_port][-1]:
            pass


   # # dst_ip_port is not in mail_auths so this must be 2nd or higher client > server pkt
   # elif src_ip_port in mail_auths:

   #         str_load = str_load.replace(r'\r\n', '')
   #         print '[%s > %s]   Mail auth: %s' % (src_ip_port, dst_ip_port, str_load)
   #         del mail_auths[seq]
   #         found = True
   #         try:
   #             decoded = base64.b64decode(str_load).replace('\x00', ' ')#[1:] # delete space at beginning
   #         except Exception:
   #             raise
   #             decoded = None
   #         if decoded != None:
   #             print '[%s > %s]   Decoded:' % (src_ip_port, dst_ip_port), decoded


    if found == True:
        return True

def irc_logins(str_load, src_ip_port, dst_ip_port):
    '''
    Find IRC logins
    '''
    user_search = re.match(irc_user_re, str_load)
    pass_search = re.match(irc_pw_re, str_load)
    if user_search:
        return user_search.group(1).strip()
    if pass_search:
        return pass_search.group(1).strip()

def other_parser(full_load, str_load, src_ip_port, ack, seq):
    '''
    Pull out pertinent info from the parsed HTTP packet data
    '''
    user_passwd = None
    http_url_req = None
    host = None
    http_methods = ['GET ', 'POST ', 'CONNECT ', 'TRACE ', 'TRACK ', 'PUT ', 'DELETE ', 'HEAD ']
    http_line, header_lines, body = parse_http_load(full_load)
    headers = headers_to_dict(header_lines)
    method, path = parse_http_line(http_line, http_methods)
    http_url_req = get_http_url(method, path, headers)
    if http_url_req:
        print http_url_req

    if body != '':
        user_passwd = get_login_pass(body)

    if len(headers) == 0:
        authenticate_header = None
        authorization_header = None
    for header in headers:
        authenticate_header = re.match(authenticate_re, header)
        authorization_header = re.match(authorization_re, header)
        if authenticate_header or authorization_header:
            break

    if authorization_header or authenticate_header:

        # NETNTLM
        parse_ntlm(authenticate_header, authorization_header, headers, ack, seq)

        # Basic Auth
        parse_basic_auth(headers, authorization_header)

        # Kerberos over TCP?
        #####################

    ############ PRINT STUFF ###############
    if user_passwd != None:
        print '  User:', user_passwd[0]
        print '  Pass:', user_passwd[1]

def parse_basic_auth(headers, authorization_header):
    '''
    Parse basic authentication over HTTP
    '''
    if authorization_header:
        header_val = headers[authorization_header.group()]
        b64_auth_re = re.match('basic (.+)', header_val, re.IGNORECASE)
        if b64_auth_re != None:
            basic_auth_b64 = b64_auth_re.group(1)
            basic_auth_creds = base64.decodestring(basic_auth_b64)
            print '  Basic Authentication:', basic_auth_creds

def parse_ntlm(authenticate_header, authorization_header, headers, ack, seq):
    '''
    Parse NTLM hashes out
    '''
    # Type 2 challenge from server
    if authenticate_header != None:
        chal_header = authenticate_header.group()
        challenge = parse_ntlm_chal_msg(headers, chal_header, ack)

    # Type 3 response from client
    elif authorization_header != None:
        resp_header = authorization_header.group()
        hash_type, crackable_hash = parse_ntlm_resp_msg(headers, resp_header, seq)
        if hash_type and crackable_hash:
            print  '  ', hash_type, crackable_hash

def parse_snmp(snmp_layer):
    '''
    Parse out the SNMP version and community string
    '''
    if type(snmp_layer.community.val) == str:
        ver = snmp_layer.version.val
        print '  SNMPv%d community string: %s' % (ver, snmp_layer.community.val)

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

def parse_ntlm_chal_msg(headers, chal_header, ack):
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

def parse_ntlm_resp_msg(headers, resp_header, seq):
    '''
    Parse the client response to the challenge
    Thanks to psychomario
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
        raise
        decoded = None
    if decoded != None:
        print '    Decoded: %s' % decoded

def printer(src_ip_port, dst_ip_port, msg):
    print '[%s>%s] %s' % (src_ip_port, dst_ip_port, msg)

def main(args):

    ############################### DEBUG ###############
    # Hit Ctrl-C while program is running and you can see
    # whatever variable you want within the IPython cli
    def signal_handler(signal, frame):
        embed()
    #    sniff(iface=conf.iface, prn=pkt_parser, store=0)
        sys.exit()
    signal.signal(signal.SIGINT, signal_handler)
    #####################################################

    # Read packets from either pcap or interface
    if args.pcap:
        try:
            pcap = rdpcap(args.pcap)
        except Exception:
            raise
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

