#!/usr/bin/python

#
# do a Get Channel Authentication Capabilities (see p142 of the IPMI v 2 spec)
# on a whole lotta channels. See below for more details.
#
#  Usage: $0 ip-address
#
# Sends request, tears up response, does a little sanity checking,
# prints out some stuff.  Lots of stuff. More stuff than you want or
# can shake a stick at.
# 
# Basically does a get-ipmi-auth.py (see other program by me in github)
# a whole lotta times. Why? Read on!
#
# Lots of comments are quotes from the most recent IPMI 2.0 spec.
# Little writeup below is mostly from a writeup I did -
#
# Hopefully some fixed results... zen - Wed Sep  3 22:38:30 PDT 2014
#
# v 1.03
#

#
# Notes on the IPMI Protocol Security Model.
# 
# I wrote in Sold Down the River about the curious aspects of channels
# and authentication and users and all that stuff. Here's a slimmed
# down model... and as a bonus a program that iterates through all
# the channels, users types, and authentication for a host, which is
# quite a bit of checking.
# 
# 
# In any case I'm almost certain that I really don't understand all
# the implications of the specification, but here's a brief summary
# of how I think it works.
# 
# User IDs are numerically based and have names (e.g. "ADMIN", "root"
# etc.) associated with them, with user ID 1/one permanently associated
# with the NULL user name. Duplicate names are allowed, and while
# some commands use IDs and others usernames, if there are ambiguities
# the system will grant or deny access or authorization based on the
# lowest matching numeric ID username that is matched by the username.
# 
# Authentication is done via a password of up to 16 or 20 characters,
# but may be bypassed or controlled on a per user and channel basis.
# Most vendors have also added support for LDAP, Active Directory,
# or Radius network authentication. Users may also be disabled
# regardless of their authentication settings.
# 
# IPMI also allows multiple channels of communication that may be
# used in different ways over different interfaces or transport
# protocols, such as the LAN, internal buses, serial lines, VLANs,
# etc. (version 1.5 only had 9 channels, while version 2.0 has 14.)
# Each channel is completely independent of the others and may operate
# in the same or different mediums.
# 
# In my testing I only examined the default channels, which are
# actually a sliver of the overall potential of what IPMI can do, so
# there may well be additional undetected problems, both similar and
# unknown, lurking out there.
# 
# While LAN and serial channels share many characteristics with the
# basic channel settings, serial users have additional options and
# limitations with respect to access, authentication, and session
# management.
# 
# Channels have an access mode associated with them, granting access
# based on the state of the server. These modes are configurable and
# include pre-boot only, always available, shared, or disabled.
# 
# There are also 5 privilege levels that are associated with commands
# and users: callback, operator, user, administrator, and an OEM/vendor
# chosen one. Each user may be granted a maximum privilege level, and
# all commands have a minimum privilege level that must be met in
# order to be executed.
# 
# There are also a set of commands to manage and limit access of other
# commands (I count over 160 commands in the specification, plus OEMs
# and vendors are free to add to the set) in the terribly and
# misleadingly named firmware firewall, which allows individual
# commands to be limited on a per channel and per user basis. Commands
# may also be bridged or routed to other interfaces and media.  IPMI
# calls the data in its protocol payloads, which in version 2 were
# greatly expanded; they may be used to transmit both IPMI and non-IPMI
# commands and data. Payloads may use their own set of port numbers,
# and transports. Non-IPMI data is perhaps most commonly used for
# Serial Over LAN (SOL), but vendors may add just about anything here.
# 
# Channels also have support for different algorithms for authentication
# as well as data confidentiality and integrity; this also is set on
# individual channels and may be set for individual sessions, command
# or payloads.
# 
# In addition the vendors have the capacity to expand the protocol
# to do whatever they want. Part of the problem with analyzing IPMI
# security is that no one outside the various vendors knows what its
# actual capabilities are.
# 
# In any case what this all creates is a rather sizeable multidimensional
# matrix of possibilities. When I first saw all this I initially
# thought that no one would use all these options, but unfortunately
# some in fact do, and I've seen different settings, configurations,
# and restrictions for users, privileges, and commands on discrete
# channels.
# 
# This sets up an unfortunate situation where you might think you
# have disabled some undesirable setting (say, cipher zero to disallow
# unauthenticated access), but you might not be looking at all the
# users or channels. Or perhaps you only disabled it for the wrong
# privilege level on the right channel. Or... pick your confusion.
# 
# I know of no software that manages or reports on all this, but to
# my eyes it vastly too complex to understand any reasonably sized
# implementation that span multiple servers. Detecting someone who
# has set up unauthorized or backdoor access by simply using stock
# IPMI commands would be a sizable challenge, and all you need is one
# command on one single channel.
# 
# I think to understand a BMC's basic channel security one would need
# to (at least):
# 
# - Enumerate through all the channels to examine all the various privilege levels assigned to commands and payloads
# 
# - Look at the cipher support for each channel and traffic
# 
# - Enumerate all the privilege constraints for each channel
# 
# - Enumerate all users, payloads, and commands on all channels and
#   map their capabilities as granted and constrained by the various
#   constraints and rights granted by the firmware firewall and other
#   commands
# 
# - Possibly do all or most of the above explicitly for both 1.5 and
#   version 2.0 of the specification, since they possibly have different
#   command flows and most definitely interpret the commands differently
#   at times.
#
#   In this version I cowardly stop if 2.0 answers, since it generally
#   gives out more information than 1.5... probably should do both,
#   but it spot checks it all seemed a bit insane, lol.
# 
# Mind you, doing all of this on a BMC might well crash or wedge it
# into a sullen silence, as they are very easy to DoS into submission
# even unwittingly (I've completely broken BMCs from my testing both
# Dell and HP servers.)
# 
# The python program on git does at least some of this... for only
# one command, one that they all have to answer (RE: the spec, at
# least), but it really should be done 160 times or so, one for each
# command. And I don't know the usernames a priori, so I basically
# just ignore them as well. Still... I found the results somewhat
# interesting.
#


from socket import *

import binascii

import sys

BYTE_SIZE = 8
verbose   = 0

try:
  target = sys.argv[1]
except:
   print("usage: %s target" % sys.argv[0])
   exit(1)

# in seconds
timeout = 10
# udp
PORT    = 623

# get chan auth packet... snuffled from tcpdump & wireshark traffic

# 8e = 2.0
# 04, ADMIN
payload20 = "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5"

# 0e = 1.5
# 04, ADMIN
payload15 = "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x0e\x04\x35"


payload = ""
data    = ""

#
# Table 5-2, Completion Codes
# Intelligent Platform Management Interface Specification
# Code        Definition
# GENERIC COMPLETION CODES 00h, C0h-FFh
#

completion_codes = {}

completion_codes = {
    "\x00": "Command Completed Normally.",
    "\xc0": "Node Busy. Command could not be processed because command processing resources are temporarily unavailable.",
    "\xc1": "Invalid Command. Used to indicate an unrecognized or unsupported command.",
    "\xc2": "Command invalid for given LUN.",
    "\xc3": "Timeout while processing command. Response unavailable.",
    "\xc4": "Out of space. Command could not be completed because of a lack of storage space required to execute the given command operation.",
    "\xc5": "Reservation Canceled or Invalid Reservation ID.",
    "\xc6": "Request data truncated.",
    "\xc7": "Request data length invalid.",
    "\xc8": "Request data field length limit exceeded.",
    "\xc9": "Parameter out of range. One or more parameters in the data field of the Request are out of range.",
    "\xcA": "Cannot return number of requested data bytes.",
    "\xcB": "Requested Sensor, data, or record not present.",
    "\xcC": "Invalid data field in Request",
    "\xcD": "Command illegal for specified sensor or record type.",
    "\xcE": "Command response could not be provided.",
    "\xcF": "Cannot execute duplicated request. This completion code is for devices which cannot return the response that was returned for the original instance of the request. Such devices should provide separate commands that allow the completion status of the original request to be determined. An Event Receiver does not use this completion code, but returns the 00h completion code in the response to (valid) duplicated requests.",
    "\xc0": "Command response could not be provided. SDR Repository in update mode.",
    "\xc1": "Command response could not be provided. Device in firmware update mode.",
    "\xc2": "Command response could not be provided. BMC initialization or initialization agent in progress.",
    "\xc3": "Destination unavailable. Cannot deliver request to selected destination. E.g. this code can be returned if a request message is targeted to SMS, but receive message queue reception is disabled for the particular channel.",
    "\xc4": "Cannot execute command. Insufficient privilege level.",
    "\xc5": "Cannot execute command. Command, or request parameter(s), not supported in present state.",
    "\xcF": "Unspecified error.",
# DEVICE-SPECIFIC (OEM) CODES 01h-7Eh
# won't match (need regexp)... see if we need them
    "\x01-\x7e": "Device specific (OEM) completion codes. This range is used for command-specific codes that are also specific for a particular device and version. A-priori knowledge of the device command set is required for interpretation of these codes.",
# COMMAND-SPECIFIC CODES 80h-BEh
# won't match (need regexp)... see if we need them
    "\x80-\xbe": "Standard command-specific codes. This range is reserved for command-specific completion codes for commands specified in this document."
};


##### cipher stuff here

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
def build_me_a_rocket(offset, chan):
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
    # channel_number = "\x0e"
    channel_number = chan

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


def cipher_sendoff(chan):

    #
    # attemp to create socket, bind & send
    #
   try:
   
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
                   print('building and sending packet %d on channel %d' % (i, ord(chan)))
       
               #
               # set off that rocket
               #
               payload = build_me_a_rocket(offset, chan)
       
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
                   # print("The remote system doesn't appear to support the Get Channel Cipher Suites command")
                   # sys.exit(2)
                   return(2)
       
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
   
   except Exception, e:
       sys.stderr.write("hmmm.... problems in cipher_sendoff, tonto: %s, bailin'" % e)
       # sys.exit(3)
       return(3)

   cipher_rip(all_data)


def cipher_rip(all_data):
   #
   # got the data... part II, parse it!
   #

   if all_data == "":
      return
   
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
   IANA_id        = "N/A"
   
   n = 0
   
   
   #
   #
   #
   def print_line (cid):
       # ID     IANA       Auth Alg  Integrity Alg Confidentiality Alg
       cid = str(int(cid,16)).ljust(5, ' ')
       print(cid + IANA_id.ljust(8, ' ') + authentication.ljust(16, ' ') + integrity.ljust(17, ' ') + encryption)
   
   
   # header line
   print("ID   IANA    Auth Alg        Integrity Alg   Confidentiality Alg")
   
   # loop over output 2 chars at a time
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
               print_line(last_cipher)
               all_cids.add(last_cipher)
   
           authentication = ""
           integrity      = ""
           encryption     = ""
           IANA_id        = "N/A"
   
           n = n + 1
           continue
   
       elif nibble == 'c1':
           #print('\nstart of OEM record byte')
           last_cipher = cipher_id
   
           OEM = all_data[n_byte+2:n_byte+5]
           # print('Not tested - OEM => ' + OEM)
           # print('\tskipping ahead 3 bytes')
   
           IANA_id = all_data[n_byte+5:n_byte+7]
   
           # if cipher_id not in all_cids and all_cids:
           if last_cipher not in all_cids and authentication != "" and integrity != "" and encryption != "" :
               print_line(last_cipher)
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
               authentication = ipmi_auth_algorithms[str(alg)]
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
               integrity = ipmi_integrity_algorithms[str(alg)]
           elif verbose:
               print('warning... multiple integrity fields...?\tIntegrity: ' + ipmi_integrity_algorithms[str(alg)])
   
       elif nibble[0] == "8":
           alg = int(nibble[1],16) & 0x3F
           if encryption == "":
               encryption = ipmi_encryption_algorithms[str(alg)]
           elif verbose:
               print('warning... multiple encryption fields...?\tEncryption: ' + ipmi_encryption_algorithms[str(alg)])
   
       n_record = n_record + 4
    
       if n_record == 16:
           n_record = 0
   
   if cipher_id not in all_cids and authentication != "" and integrity != "" and encryption != "" :
       print_line(cipher_id)
   


#
# helper function, just looks up a position in a string, which
# is representing a byte of network data.
#
# The function returns the bit at position X; position 0 == least significant
#
# lots of assumptions!  #1 is that byte is 8 bits, #2 is that the bits are in a certain order
#
def check_bit(byte, position):

   if position > BYTE_SIZE:
      print("out-of-byte-bounds (%s)" % position)
      return(-1)

   byte = bin(byte)[2:].rjust(8, '0')[::-1]

   #
   # make a string of bits that make up the bytes; flip byte
   # so bit[0] = LSD (least-sig-digit)
   #
   # print("\tB:"),
   # print(byte)

   if byte[position] == "1":
      return(1)

   return(0)

#
# send the ol' packet
#
def packety_send(target, packet):

   # set er up
   global udp
   global data

   udp = socket(AF_INET, SOCK_DGRAM)
   sake = udp.getsockname()
   udp.bind(sake)

   # actually send packet
   try:

      #  import pdb
      #  pdb.set_trace()
   
      udp.settimeout(timeout)
      # if udp.sendto(" ", (target, PORT)) <= 0:
      if udp.sendto(packet, (target, PORT)) <= 0:
         print("couldn't send packet to %s" % target)
      # catch response
      data,addr = udp.recvfrom(512)
      # 06 00 ff 07 00 00 00 00  00 00 00 00 00 10 81 1c 63 20 00 38 00 02 15 04  00 00 00 00 00 8d 0a
      udp.close()

      return(0)

   #
   # exception to the net stuff
   #
   except Exception, e:
      print("hmmm.... problems in paradise, tonto: %s, bailin'" % e)
      # exit(2)
      return(1)
   
   return(1)

#
# fair or foul ball?
#
def rip_packet():

   #
   # create socket & bind to local port
   #

   if not len(data):
      print("no data to work with, exiting")
      return(2)

   try:
   
      # the rest is taken from the spec
      rmcp       = data[0:4]
   
      if rmcp != "\x06\x00\xff\x07":
         print("not a valid RMCP message")
         exit(2)
   
      comp_code   = data[20]
   
      if comp_code != "\x00":
         # this 
         # print("remote system unable to comply with request (error code %s)" % hex(ord(comp_code)))

         # common errors, ignore
         if comp_code == '\xc9' or comp_code == '\xcC':
            return(comp_code)

         try:
            print "IPMI protocol error: %s" % completion_codes[comp_code]
            return
         except Exception, e:
            print("Remote system unable to comply with request (error code %s)" % hex(ord(comp_code)))

         return(comp_code)
   
      auth_type   = data[4]
      seq_num     = data[5:9]
      session_id  = data[9:13]
      mesg_len    = ord(data[13])
      target_addr = data[14]
      target_LUN  = data[15]
      header_chk  = data[16]
      src_addr    = data[17]
      src_LUN     = data[18]
      command     = data[19]
   
      if command != "\x38":
         print("this isn't a Get Channel Authentication Capabilities response")
         exit(3)
   
      response    = data[21:21+mesg_len]
   
   #  import pdb
   #  pdb.set_trace()
   
      parse_response(response)
   
   #
   # exceptions... this should also catch parsing stuff in parse_response
   #
   except Exception, e:
      print("hmmm.... problems in paradise parsing the return traffic, tonto: %s, bailin'" % e)
      exit(2)

#
# all the action goes here... if get a response, rip it up,
# compare it to the IPMI spec to see if it makes sense.
#
def parse_response(packet):

#  import pdb
#  pdb.set_trace()

   # sum of problems found
   problems = 0

   # assume not until proven otherwise
   ipmi20_support = 0

   #
   # Channel Number
   #
   # Channel number that the Authentication Capabilities is being
   # returned for. If the channel number in the request was set to
   # Eh, this will return the channel number for the channel that the
   # request was received on.
   #
   channel = ord(packet[0])

   print("Ch-%s\t" % channel),

   #
   # Authentication Type Support
   #
   # Bit-by-bit breakdown of this byte

   # [7]          1b = IPMI v2.0+ extended capabilities available.
   #              0b = IPMI v1.5 support only.
   #
   # [6]          reserved
   #
   # [5]          OEM proprietary (per OEM identified by the IANA OEM ID in the RMCP Ping Response)
   # [4]          straight password / key
   # [3]          reserved
   # [2]          MD5
   # [1]          MD2
   # [0]          none
   #
   auth_support = ord(packet[1])

   # does it support IPMI v20 extended commands?
   if check_bit(auth_support, 7):
      ipmi20_support = 1
      backward_ipmi15_support = 1

   print("1.5"),
   if ipmi20_support or proto_version == payload20:
      print("-2.0"),

   # print("\tIPMI 2.0 extended data:")
   if check_bit(auth_support, 0):
      print("\tNo auth*"),
      problems += 1
   if check_bit(auth_support, 1):
      print("\tMD2*"),
      problems += 1
   if check_bit(auth_support, 2):
      print("\tMD5"),
   if check_bit(auth_support, 4):
      print("\t*str8 pass"),
      problems += 1
   if check_bit(auth_support, 5):
      print("\t*OEM auth"),   # maybe good, maybe not
      problems += 1
   if check_bit(auth_support, 6):
      print("*\tUsing funky reserved bit, maybe trouble?")

   #
   # next thingee... this byte is a bit overloaded, so
   # it has a few things here.
   #
   # Bit-by-bit breakdown from spec:
   #
   #  [7:6] - reserved
   #    [5] - KG status (two-key login status). Applies to v2.0/RMCP+ RAKP Authentication only. Otherwise, ignore as "reserved".
   #
	#        0b = KG is set to default (all zeros). User key KUID will be used in place of KG in RAKP
	#        1b = KG is set to non-zero value. (Knowledge of both KG and user password (if not anonymous login) required for activating session.)
   #
	# Following bits apply to IPMI v1.5 and v2.0:
	#
	# [4] - Per-message Authentication status
	#       0b = Per-message Authentication is enabled
	#       1b = Per-message Authentication is disabled
	#
	# [3] - User Level Authentication status
	#       0b = User Level Authentication is enabled
	#       1b = User Level Authentication is disabled
   #
   # On UL Auth the spec says:
   #
   #     In many cases, there is little concern about whether User Level
   #     commands are authenticated, since the User privilege allows
   #     status to be retrieved, but cannot be used to cause actions such
   #     as platform resets, or change platform configuration. Thus, an
   #     option is provided to disable authentication just for User Level
   #     commands. If User Level Authentication is disabled, then User
   #     Level messages will be accepted that have the Authentication
   #     Type set to NONE.
   #
   # Among the user-level commands are information gathering requests
   # that can reveal quite a lot about the BMC and system - page 586
   # of the spec has all the details.  Do not leave this disbled.
   #

	# 
	# [2:0] - Anonymous Login status
	#
	# [2]   1b = Non-null usernames enabled. (One or more users are enabled that have non-null usernames).
	#
	# [1]   1b = Null usernames enabled (One or more users that have a null username, but non-null password, are presently enabled)
	#
	# [0]   1b = Anonymous Login enabled (A user that has a null username and null password is presently enabled)
	#
   auth_stuff = ord(packet[2])

   #
   # if !IPMI 2.0/RMCP+ RAKP ignore
   #
   if ipmi20_support:
      if check_bit(auth_stuff, 5):
         print("\t*KG-0s"),
         problems += 1
      else:
         print("\t!0 KG key!"),

   # both 1.5/2.0
   if check_bit(auth_stuff, 4):
      print("\t*!per-msg-auth!"),
      problems += 1
   else:
      print("\tper-mess-auth"),

   if check_bit(auth_stuff, 3):
      print("\t*!user-auth!"),
      problems += 1
   else:
      print("\tuser-auth"),

   if check_bit(auth_stuff, 2):
      print("\tnon-null-user"),
   else:
      print("\t*non-null-allowed"),
      problems += 1

   if check_bit(auth_stuff, 6):
      print("\t*!anon!"),
      problems += 1
   else:
      print("\tanon"),

   if problems > 0:
      print('')

#  if problems > 0:
#     suffix = ""
#     if problems > 1:
#        suffix = "s"
#     print("%s\t%s problem%s found (marked with *'s)" % (target, problems, suffix)),
#  else:
#     print("%s\tNo problems found" % target)


def ipmi_checksum(data):
   sum = 0

   # only IPMI bytes!
   for byte in data[14:]:
      sum += ord(byte)

   sum = ~sum + 1
   check = "%s" % chr(sum & 0xff)

   return(check)


#
# ok, ball time - throw!
#


   #
   # try 2.0 first
   #
 
# for priv in ["\x01", "\x02", "\x03", "\x04", "\x05"]:

priv_levels = ['CALLBACK', 'USER', 'OPERATOR', 'ADMINISTRATOR', 'OEM']

# a bit absurd... but that's IPMI for you

# IPMI gave 0-7 and 15 as valid channels, 2.0 gives 0-B (e.g. 12) + 15.
# for channel in [0, 1, 2, 3, 4, 5, 6, 7, 15]:

# if you specify "E" in you get the channel the request is issued on (usually over LAN);
# 2.0 allows you to set the top of the hex byte to get extended stuff back
# for channel in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15]:
for channel in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15]:

   n = 0

   good_channel = True

   for priv in ["\x01", "\x02", "\x03", "\x04", "\x05"]:

      print('checking channel %d with priviledge level %s' % (channel, priv_levels[n]))

      n += 1

      payload20 = "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38" + chr(channel) + priv
      payload15 = "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38" + chr(channel) + priv

      payload20 = payload20 + ipmi_checksum(payload20)
      payload15 = payload15 + ipmi_checksum(payload15)

      for proto_version in payload20, payload15:
      
         # pack up the bags and give up on this channel
         if packety_send(target, proto_version):
            print("problems with send...")
            good_channel = False
            break
      
         #
         # try to catch
         #
         cc = rip_packet()
      
         # looks good!
         if cc == 0 or cc == None:
            print("Version 2.0 accepted, not going to try 1.5")
            break
            # exit(0)
            
         elif cc == "\xcc" and proto_version == payload20:
            if verbose:
               print("Version 2.0 not accepted, trying 1.5")


   # get cipher support
   if good_channel:
      cipher_sendoff(chr(channel))


