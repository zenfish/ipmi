#!/usr/bin/python

#
# do a Get Channel Authentication Capabilities (see p142 of the IPMI v 2 spec)
#
#  Usage: $0 ip-address
#
# Sends request, tears up response, does a little sanity checking, prints out some stuff
#
# Lots of comments are quotes from the most recent IPMI 2.0 spec.
#
# Hopefully some fixed results... zen - Wed Jun 26 19:02:27 PDT 2013
#
# v 1.02
#

from socket import *
import sys

BYTE_SIZE = 8
verbose   = 1

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

   # print("\t\tchecking %s[%d]:" % (byte, position)),
   byte = bin(byte)[2:].rjust(8, '0')[::-1]
   # print("\tbits => " + byte),

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
      exit(2)
   
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
      exit(2)

   try:
   
      # the rest is taken from the spec
      rmcp       = data[0:4]
   
      if rmcp != "\x06\x00\xff\x07":
         print("not a valid RMCP message")
         exit(2)
   
      comp_code   = data[20]
   
      if comp_code != "\x00":
         print("remote system unable to comply with request (error code %s)" % hex(ord(comp_code)))
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

   print("Channel %s:" % channel),

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

   print("IPMI 1.5"),
   if ipmi20_support or proto_version == payload20:
      print("and 2.0"),

   print("are supported")

   # print("\tIPMI 2.0 extended data:")
   if check_bit(auth_support, 0):
      print("*\tNo auth is supported")
      problems += 1
   if check_bit(auth_support, 1):
      print("*\tMD2 auth supported")
      problems += 1
   if check_bit(auth_support, 2):
      print("\tMD5 auth supported")
   if check_bit(auth_support, 4):
      print("*\tstraight password/key auth supported")
      problems += 1
   if check_bit(auth_support, 5):
      print("*\tOEM auth supported (maybe it's ok, maybe not)")   # maybe good, maybe not
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
         print("*\tKG key is set to default (all 0's)")
         problems += 1
      else:
         print("\tKG key has been set to a non-zero value")

   # both 1.5/2.0
   if check_bit(auth_stuff, 4):
      print("*\tPer message auth is disabled")
      problems += 1
   else:
      print("\tPer message auth is enabled")

   if check_bit(auth_stuff, 3):
      print("*\tUser lvl auth is disabled")
      problems += 1
   else:
      print("\tUser lvl auth is enabled")

   if check_bit(auth_stuff, 2):
      print("\tNon-null usernames enabled")
   else:
      print("*\tnull usernames allowed")
      problems += 1

   if check_bit(auth_stuff, 6):
      print("*\tAnonymous login enabled (really bad: a user that has a null username & password is enabled!)")
      problems += 1
   else:
      print("\tAnonymous login disabled")

   if problems > 0:
      print("%s\t%s problems found (marked with *'s)" % (target, problems))
   else:
      print("%s\tNo problems found" % target)

#
# ok, ball time - throw!
#

#
# try 2.0 first
#

for proto_version in payload20, payload15:

   if packety_send(target, proto_version):
      next

   #
   # try to catch
   #
   cc = rip_packet()

   # looks good!
   if cc == 0 or cc == None:
      exit(0)
      
   elif cc == "\xcc" and proto_version == payload20:
      if verbose:
         print("Version 2.0 not accepted, trying 1.5")

      # packety_send(target, proto_version)
#  else:
#     print("Error: %s completion code from remote" % hex(ord(cc)))
#     exit(4)


