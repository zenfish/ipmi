#!/usr/bin/env python

#
# Do a Get Device ID (see p250 of the IPMI v 2 spec) on a host
#
#       Usage: $0 ip-address
#
# Outputs the target and the GUID in one long string as well as broken 
# up (tab sep'd); something that looks like:
#
#   10.0.0.1    373030314d530025903eeba000000000    37303031-4d53-0025-903e-eba000000000
#
# (Usually I'd simply emit the GUID, but I was lazy and this made it
# easier when scripting, just change the print at the bottom if you
# want to change it.)
#
# RFC 4122 specifies four different versions of UUID formats and
# generation algorightms suitable for use for a Device GUID in
# IPMI.  These are version 1 (0001b) "time based" - and three
# "name-based" versions: version 3 (0011b) "MD5 hash", version 4
# (0100b) "Pseudo-random", and version 5 "SHA1 hash". The version 1
# format is recommended. However, versions 3, 4, or 5 formats are
# also allowed.
#
# Supposedly this is something like this - which illustrates the
# time-based version... they aren't grouped like that in ipmiutil,
# but who knows, really.
#
#       Table 20-10, GUID Format
#
#   GUID byte   Field                   MSbyte
#       1       node
#       2       node
#       3       node
#       4       node
#       5       node
#       6       node    MSbyte
#       7       clock seq and reserved
#       8       clock seq and reserved  MSbyte
#       9       time high and version
#       10      time high and version   MSbyte
#       11      time mid
#       12      time mid                MSbyte
#       13      time low
#       14      time low
#       15      time low
#       16      time low                MSbyte
#
# The RFC shows it as:
#
#  0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          time_low                             |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |       time_mid                |         time_hi_and_version   |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                         node (2-5)                            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Name-based ones can be, among other things, derived from X500,
# ISO OIDs, URLs, or FQDNs (appendix C in RFC 4122.)
#
#
#
# Anyway, back to the fun.
#
# This DOES NOT USE AUTHENTICATION. This is as per spec; the command is
# "highly recommended", but not mandatory. I think some require auth
# despite spec, which is what I'd recommend vendors use :)
#
# The GUID is a Vendor Specific ID - "A unique number per device".
# "A Device GUID should never change over the lifetime of the device",
# which makes it a remarkable thing if true; IP addresses, even MAC addrs,
# are crappy network IDs.
#
# This script simply sends request, tears up response, does a little sanity 
# checking, prints out some stuff.  Comments are often quotes from
# the IPMI 2.0 spec. The output steals the format from ipmiutil...
# no idea why some bytes are reversed and others aren't, even after
# studying spec. Par for the course.
#

import sys
from   socket    import *

try:
  target = sys.argv[1]
except:
   print("usage: %s target" % sys.argv[0])
   exit(1)

# in seconds
timeout = 10
timeout = 5
# udp
PORT    = 623

#
# parts of the packet below
#

# RMCP class IPMI
rmcp_class   = "\x06\x00\xff\x07"
auth_type    = "\x00"
session_num  = "\x00\x00\x00\x00"
session_id   = "\x00\x00\x00\x00"

message_len  = "\x07"    # bytes of stuff below

target_addr  = "\x20"
lun_netfn    = "\x18"   # LUN & NetFn
header_chksm = "\xc8"
source_addr  = "\x81"
source_lun   = "\x00"

#
#  08h = get device guid - works unauth'd on SM!
#  37h = get system guid
#  25h = get watchdog timer - works on HP ilo2
#  0ah = get command support
#  2fh = get BMC global enables
#
ipmi_cmd     = "\x37"

# checksum fu swiped from jarrod/xcat - http://sourceforge.net/p/xcat/code/HEAD/tree/xcat-core/trunk/xCAT-server/lib/perl/xCAT/IPMI.pm
sum = 0;
for byte in target_addr + lun_netfn + header_chksm + source_addr + source_lun + ipmi_cmd:
   sum += ord(byte)
sum = ~sum + 1
checksum = "%s" % chr(sum & 0xff)

# IPMI v1.5 session wrapper
payload = rmcp_class + auth_type + session_num + session_id + message_len +   \
          target_addr + lun_netfn + header_chksm + source_addr + source_lun + \
          ipmi_cmd + checksum

#
# create socket & bind to local port
#

udp  = socket(AF_INET, SOCK_DGRAM)
sake = udp.getsockname()
udp.bind(sake)

#
# swap pairs of hex digits
#
def swap(s):
   # print('\tbefore ' + s)
   s = "".join(reversed([s[i:i+2] for i in range(0, len(s), 2)]))
   # print('\tafter ' + s)
   return(s)

#
# send packet... or die trying
#
try:
   udp.settimeout(timeout)

   # if udp.sendto(" ", (target, PORT)) <= 0:
   if udp.sendto(payload, (target, PORT)) <= 0:
      print("couldn't send packet to %s" % target)

   # catch response
   data,addr = udp.recvfrom(512)

#  print(data)

   # skip the header
   data = data[21:-1]

   guid = data.encode('hex')

   #
   # in "Wired for Management Baseline", they say:
   #
   #  Field                      Data Type                Octet #       Note
   #  ------                     ----------               --------      -----
   #  time_low                   unsigned 32 bit integer   0-3          The low field of the timestamp.
   #  time_mid                   unsigned 16 bit integer   4-5          The middle field of the timestamp.
   #  time_hi_and_version        unsigned 16 bit integer   6-7          The high field of the timestamp multiplexed with the version number.
   #  clock_seq_hi_and_reserved  unsigned 8 bit integer     8           The high field of the clock sequence multiplexed with the variant.
   #  clock_seq_low              unsigned 8 bit integer     9           The low field of the clock sequence.
   #  node                       unsigned 48 bit integer   10-15        The spatially unique node identifier.

   #
   # IPMI reverses some of these... sure, why not... that makes sense
   #

   # print('len of data to work with: %s\n' % len(data))

   # node          = swap(data[0:4].encode('hex'))

   node          = data[0:4].encode('hex')

   # print('nodey ' + node)

   clock_seq     = swap(data[4:5].encode('hex'))
   reserved      = swap(data[5:6].encode('hex'))

   time_hi       = swap(data[6:7].encode('hex'))
   version       = swap(data[7:8].encode('hex'))

   time_mid      = data[8:10].encode('hex')


   time_low      = data[10:].encode('hex')

   # one big string & IPMIutil formatting style
   print("%s\t%s\t%s-%s%s-%s%s-%s-%s" %
        (target, node + clock_seq + reserved + time_hi + version + time_mid + time_low,
         node, clock_seq, reserved, time_hi, version, time_mid, time_low))


   udp.close()

#
# ... this should also catch parsing stuff in parse_response
#
except Exception, e:
   sys.stderr.write("%s - hmmm.... problems in IPMI paradise, tonto: %s, bailin'\n" % (target, e))

