#!/usr/bin/env python

#
# A simple IPMI auditor, or perhaps configuration file checker.
#
# Takes the JSON output from "ipmifreely.py" and
# the policy-ish statements from "IPMI-policy.ini"
# and says what it finds might be amiss.
#
# Usage is simply:
#
#   $0 json-file
#

import simplejson as json

import ConfigParser
import re
import sys

usage = "Usage: %s json-file" % sys.argv[0]

debug   = 0
verbose = 0

#
# read in policy data
#
policy_file = "IPMI-policy.ini"
policies = ConfigParser.ConfigParser()
# this weird one is to preserve case
policies.optionxform = str
if not policies.read(policy_file):
   print ("...ack... can't ... breath... policy file '%s' not found... keeling over now... *thump*" % policy_file)
   exit(1)

# tools used to gather data
tools = {'ipmi-chassis-config':0, 
         'bmc-config':0, 
         'pef-config':0, 
         'ipmi-sensors-config':0}

# open the json file or die
try:
   f = open(sys.argv[1], 'r').read()
except:
   print(usage)
   exit(1)
config = json.loads(f)


#
# do a check to see if a regexp matches a string
#
# if ignore = True, then ignore case
#
def check_policy(value, regexp, ignore = False):

   if verbose:
      print("in check_value; does '%s' match regexp:%s: ???" % (value, regexp))

   if ignore:
      token = re.compile(regexp, re.IGNORECASE)
   else:
      token = re.compile(regexp)

   if not token.search(value):
      if debug:
         print("match")
      return True
   else:
      if debug:
         print("no... match")
      return False

#
# do a policy check against a section from the free-ipmi tools
#
def check_section(tool, section):

   if verbose:
      print("in check section[%s]: %s" % (tool, section))

# *** in check section[bmc-config]: Lan_Conf_Security_Keys

   try:
      policy = dict(policies.items(section))
      if debug:
         print(policy)
   except:
      if debug:
         print("no policy statements for %s" % section)
      return

   for item in policy:
      if debug:
         print("\tchecking :%s: => :%s:" % (item, policy[item]))

      try:
         if check_policy(config[tool][section][item], policy[item]):
            print("[%s]\t%s\t%s\t= %s" % (tool, section, item, config[tool][section][item]))
      except:
         if debug:
            print('no conf')
         # print('go boom')

#
# actually do some checks
#
all_sections = []

for section in config:
   # one of these is the host....
   try:
      tools[section]
      all_sections.append(section)
   except:
      print("Host:\t\t%s" % section)

if verbose:
    print ("Tools run:\t%s" % all_sections)

for tool in tools:
   for section in config[tool]:
      # print('sex ' + section)
      check_section(tool, section)

