#!/usr/bin/python

# do an unauthenticated Get Channel Cipher Suites command

#
# Options:
#
#  -t timeout           Timeout after N seconds (defaults to 60)
#  -v                   Verbose
#  -version             Print version #
#  -h/--help            help
#

# zen@fish2.com, Mon May 12 11:53:22 PDT 2014

from   socket import *

import getopt
import binascii
import sys

timeout  = 10    # in seconds
version = "0.1"
PORT     = 623   # udp

verbose = False

arg_string = "t:v"
arg_usage  = "[-t timeout] [-v] [-version] [-h|--help]target"
usage      = "Usage: %s %s" % (sys.argv[0], arg_usage)

try:
    opts, args = getopt.getopt(sys.argv[1:], arg_string, ["help"])

except getopt.GetoptError as err:
    print(str(err)) # will print something like "option -a not recognized"
    print(usage)
    sys.exit(2)

for opt, argh in opts:

    if opt == "-t":
        timeout = argh

    elif opt == "-v":
        verbose = True

    elif opt == "-verbose":
        verbose = True

    elif opt in ("--version", "-version"):
        print("version %s" % version)
        sys.exit(0)

    elif opt in ("-h", "--help"):
        print(usage)
        sys.exit(0)

    else:
        print("%s is an unknown option, or -h or --help for usage" % opt)
        sys.exit(1)

try:
    target = (args[0])
except:
    print(usage)
    exit(1)


#
# Constant names and lookups stolen from ipmitool-1.8.11 source code,
# which in turn were taken from the ipmi spec... what goes around
# comes around

#
# From table 13-17 of the IPMI spec
#
IPMI_AUTH_RAKP_NONE        = "0"
IPMI_AUTH_RAKP_HMAC_SHA1   = "1"
IPMI_AUTH_RAKP_HMAC_MD5    = "2"
IPMI_AUTH_RAKP_HMAC_SHA256 = "3"    # not in ipmitool???

#
# From table 13-18 of the IPMI spec
#
IPMI_INTEGRITY_NONE            = "0"
IPMI_INTEGRITY_HMAC_SHA1_96    = "1"
IPMI_INTEGRITY_HMAC_MD5_128    = "2"
IPMI_INTEGRITY_MD5_128         = "3"
IPMI_INTEGRITY_HMAC_SHA256_128 = "4"   # not in ipmitool
#
# From table 13-19 of the IPMI v2 specfication
#
IPMI_CRYPT_NONE             = "0"
IPMI_CRYPT_AES_CBC_128      = "1"
IPMI_CRYPT_XRC4_128         = "2"
IPMI_CRYPT_XRC4_40          = "3"

ipmi_auth_algorithms = { 
      IPMI_AUTH_RAKP_NONE        : "none",
      IPMI_AUTH_RAKP_HMAC_SHA1   : "hmac-sha1",
      IPMI_AUTH_RAKP_HMAC_MD5    : "hmac-md5",
      IPMI_AUTH_RAKP_HMAC_SHA256 : "hmac-sha256",
      # "00" : "NULL"
}
ipmi_integrity_algorithms = {
      IPMI_INTEGRITY_NONE            : "none",
      IPMI_INTEGRITY_HMAC_SHA1_96    : "hmac-sha1-96",
      IPMI_INTEGRITY_HMAC_MD5_128    : "hmac-md5-128",
      IPMI_INTEGRITY_MD5_128         : "md5-128",
      IPMI_INTEGRITY_HMAC_SHA256_128 : "hmac-sha256-128",
      # "00" : "NULL"
}
ipmi_encryption_algorithms = {
      IPMI_CRYPT_NONE        : "none",
      IPMI_CRYPT_AES_CBC_128 : "aes-cbc-128",
      IPMI_CRYPT_XRC4_128    : "xrc4-128",
      IPMI_CRYPT_XRC4_40     : "xrc4-40",
      # "00" : "NULL"
}

#
# construct a rocket, er, packet from spare parts we have lying around
#
def build_me_a_rocket(offset):
    #
    # parts of the packet below
    #

    payload = ""
    
    # RMCP class IPMI
    rmcp_class   = "\x06\x00\xff\x07"
    auth_type    = "\x00"
    session_num  = "\x00\x00\x00\x00"
    session_id   = "\x00\x00\x00\x00"
    
    # message_len  = "\x0a"    # bytes of stuff below
    message_len  = "\x09"    # bytes of stuff below
    message_len  = "\x0a"    # bytes of stuff below
    
    target_addr  = "\x20"
    lun_netfn    = "\x18"   # LUN & NetFn
    header_chksm = "\xc8"
    source_addr  = "\x81"
    source_lun   = "\x00"
    
    #
    #  54h = get channel cipher suites
    #
    ipmi_cmd     = "\x54"
    
    #
    # get channel authentication capabilities
    #
    channel_number = "\x0e" # for ipmi v1.5
    channel_number = "\x8e" # for ipmi v2.0, should be backwards compat
    max_priv_level = "\x04" # 4h = Administrator
    ipmi_data      = channel_number + max_priv_level
    
    #
    # get channel cipher suites command
    #
    # a hex "E" here sends back the data on the channel that it was received on
    # ... might be interesting to checkout other channels...?
    channel_number = "\x0e"

    #
    # The Payload Type number is used to look up the Security Algorithm support 
    # when establishing a separate session for a given payload type.
    #
    payload_type   = "\x00"
    
    #
    #  0000 0000   two byte pairs
    #  x... ....   1=List algorithms by Cipher Suite, 0=list supported algorithms
    #  .x.. ....   reserved
    #  ..xx xxxx   List index (00h-3Fh). 0h selects the first set of 16, 1h selects 
    #              the next set of 16, and so on. 00h = Get first set of algorithm 
    #              numbers. The BMC returns sixteen (16) bytes at a time per index, 
    #              starting from index 00h, until the list data is exhausted, at 
    #              which point it will 0 bytes or <16 bytes of list data.
    #
    list_index = chr(ord('\x80') + offset)

    # print(type(list_index), type(channel_number), type(payload_type))

    ipmi_data      = channel_number + payload_type + list_index

    sum = 0;
    for byte in target_addr + lun_netfn + header_chksm + source_addr + source_lun + ipmi_cmd + ipmi_data:
        sum += ord(byte)
    sum = ~sum + 1
    checksum = "%s" % chr(sum & 0xff)
    
    # IPMI v1.5 session wrapper
    payload = rmcp_class + auth_type + session_num + session_id + message_len +   \
               target_addr + lun_netfn + header_chksm + source_addr + source_lun + \
               ipmi_cmd + ipmi_data + checksum
    
    return(payload)

#
# create socket & bind
#

udp  = socket(AF_INET, SOCK_DGRAM)
sake = udp.getsockname()
udp.bind(sake)
udp.settimeout(timeout)

auth     = ""
integ    = ""
conf     = ""
payload  = ""
all_data = ""
data     = ""

n       = 0
offset  = 0x00

#
# finally... actually send packets
#
# I should really just keep sending them until I get
# an error or to the end... but I don't trust me and the target ;)
# this should get pretty much all of the data
#
for i in range(1,16):

        n = n + 1

        if verbose:
            print('building and sending packet %d' % i)

        #
        # set off that rocket
        #
        try:
            payload = build_me_a_rocket(offset)

        except Exception, e:
            print("hmmm.... problems in paradise, tonto: %s, bailin'" % e)
            sys.exit(3)

        # if udp.sendto(" ", (target, PORT)) <= 0:
        if udp.sendto(payload, (target, PORT)) <= 0:
            print("couldn't send packet to %s" % target)

        # catch response
        data,addr = udp.recvfrom(512)

        # skip the header
        data = binascii.hexlify(data[20:])

        # print(data)

        # chop the crc
        data = data[:-2]

        completion_code = data[0:2]
        channel         = data[2:4]

        if completion_code == "c1":
            print("The remote system doesn't appear to support the Get Channel Cipher Suites command")
            sys.exit(2)

        # minus completion code and channel #
        all_data = all_data + data[4:]

        if verbose:
            print('chunk [%d]: %s' % (n, data[4:]))

        if len(data) != 36:
            # print('remote out of data %d' % len(data))
            if verbose:
                print('all data received (%d bytes): %s' % (len(all_data), all_data))
            break

        # print data + '   <---'

        # print "CC:   %s" % completion_code
        # print "Chan: %s" % channel

        offset = offset + 0x01

udp.close()

#
# got the data... part II, parse it!
#

N_spaces = 10
OEM       = ""
cipher_id = ""
nibble    = ""

all_cids = set()

cipher_id = ""

# two chars per byte
bytes = int(len(all_data) / 2)

record_len     = 16 # 16 bytes, 32 chars
n_record       = 0
current_record = 0

all_cids.add("")

authentication = ""
integrity      = ""
encryption     = ""

n = 0

print("ID\tAuth Alg\tIntegrity Alg\tConfidentiality Alg")

while n < bytes:
    # print (n)
    n_byte = n * 2
    nibble = all_data[n_byte:n_byte+2]

    n = n + 1

#   print('N: ', nibble, n)

    if nibble == 'c0':
        last_cipher = cipher_id

        cipher_id = all_data[n_byte+2:n_byte+4]

        # print('\nstart of record byte: %s' % cipher_id)

        # if cipher_id not in all_cids and all_cids:
        if last_cipher not in all_cids and authentication != "" and integrity != "" and encryption != "" :
            print(int(last_cipher,16)),
            print('\t' + authentication + '\t' + integrity + '\t' + encryption)
            all_cids.add(last_cipher)

        authentication = ""
        integrity      = ""
        encryption     = ""

        n = n + 1
        continue

    elif nibble == 'c1':
        #print('\nstart of OEM record byte')
        last_cipher = cipher_id

        OEM = all_data[n_byte+2:n_byte+5]
        print('OEM => ' + OEM)
        print('\tskipping ahead 3 bytes')

        cipher_id = all_data[n_byte+5:n_byte+7]

        # if cipher_id not in all_cids and all_cids:
        if last_cipher not in all_cids and authentication != "" and integrity != "" and encryption != "" :
            print(int(last_cipher,16)),
            print('\t' + authentication + '\t' + integrity + '\t' + encryption)
            all_cids.add(last_cipher)

        all_cids.add(cipher_id)

        authentication = ""
        integrity      = ""
        encryption     = ""

        n = n + 4

        continue

    if nibble[0] == "0":
        alg = int(nibble[1],16) & 0x3F
        if authentication == "":
            authentication = ipmi_auth_algorithms[str(alg)].ljust(N_spaces, ' ')
        # can't have more than one auth
        elif verbose:
            print('warning... multiple auth fields...?\tAuth: ' + ipmi_auth_algorithms[str(alg)])

    #
    # I'm taking a stand here and saying... it doesn't *seem* as though
    # you're going to have more than one auth/integ/encrypt record per 
    # record... but I don't know for sure
    #
    elif nibble[0] == "4":
        alg = int(nibble[1],16) & 0x3F
        if integrity == "":
            integrity = ipmi_integrity_algorithms[str(alg)].ljust(N_spaces, ' ')
        elif verbose:
            print('warning... multiple integrity fields...?\tIntegrity: ' + ipmi_integrity_algorithms[str(alg)])

    elif nibble[0] == "8":
        alg = int(nibble[1],16) & 0x3F
        if encryption == "":
            encryption = ipmi_encryption_algorithms[str(alg)].ljust(N_spaces, ' ')
        elif verbose:
            print('warning... multiple encryption fields...?\tEncryption: ' + ipmi_encryption_algorithms[str(alg)])

    n_record = n_record + 4
 
    if n_record == 16:
        n_record = 0

if cipher_id not in all_cids and authentication != "" and integrity != "" and encryption != "" :
    print(int(cipher_id,16)),
    print('\t' + authentication  + '\t' + integrity + '\t' + encryption)

sys.exit(0)

