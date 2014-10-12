#!/usr/bin/env python

# usage: $0 file

#
# (try to) Dump out passwords/accounts from a SM binary file;
# usually this is in /conf or /vm on the BMC, and goes by
# various names such as PSBlock, PSStore, PMConfig.dat, and
# the like.  This has *only* been tested on PSBlock files,
# but the theory appears to be the same; find the first account
# and password pair and march through the file at regular 
# intervals until you find all the matches.
#
# zen - bug fixed - Wed Jun  4 18:16:30 PDT 2014
#

import re
import sys

ACCOUNT_SIZE  = 16
PASSWD_SIZE   = 20   # IPMI 2.0
FIRST_ACCOUNT = 20   # the fun starts here
NEXT_ACCOUNT  = 64   # N bytes later
MAX_ACCOUNTS  =  9   # a guess

try:
   sm = open(sys.argv[1], "rb")

except:
   print("couldn't open %s" % sys.argv[1])
   sys.exit(2)

# skip first 84 bytes
sm.seek(FIRST_ACCOUNT,0)

# loop for accounts/passwords
for i in range(0,MAX_ACCOUNTS + 1):

   # go to the right place
   sm.seek(FIRST_ACCOUNT + i * NEXT_ACCOUNT, 0)

   # grabit
   yes_or_no = sm.read(1)
   account   = sm.read(ACCOUNT_SIZE)
   passwd    = sm.read(PASSWD_SIZE)

   if yes_or_no != '\001':
      # print("no acount found here, skipping to next")
      continue

   # strip nulls
   account = re.sub('\000*$', '', account)
   passwd  = re.sub('\000*$', '', passwd)

   # if len(account) > 0 and account[0] != '\000':
   print("Account [%d]: %s" % (i, account))
   print("Password[%d]: %s" % (i, passwd))

sm.close()

