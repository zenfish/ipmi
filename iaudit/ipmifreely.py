#!/usr/bin/env python3

#
# A command line tool to suck the configuration out of a remote BMC.
#
# Under the hood it simply runs four executables from the FreeIPMI toolkit:
#
#       bmc-config
#       pef-config
#       ipmi-sensors-config
#       ipmi-chassis-config
#
# Usage & various options:
#
#  Basic: $0 target-ip-or-host-name
#
# It puts the output into JSON and spits it out in a big glob.  You'll
# probably want to redirect it to a file, like:
#
#      ./ipmi-freely.py 10.0.0.1 > 10.0.0.1.json
#

#
#
# I tried to keep the options close to the ones used by the various IPMI
# tools out there, other than the target just being... the target, not 
# an option.
#
#
#       -c             output comma sep'd (not done; TBD?)
#  *    -d N           specify a /dev/ipmiN deve to use (defaults to 0/first)
#       -D             debug (not currently used)
#       -R             write raw output to a file
#       -E             Read username/password from IPMI_PASSWORD IPMI_USER environment variables
#       -f file        Read auth information from file
#       -h             help
#       -j             output JSON
#       -t seconds     Specify timeout for lan [default=2] / lanplus [default=1] interface
#       -P             port
#       -p             password
#       -r num         Set the number of retries for lan/lanplus interface [default=0]
#       -t num         Try this many times - set the number of failures overall before bailing
#       -u             username
#       -V             version of this tool
#

# dependin' on others
from   collections import defaultdict, OrderedDict, namedtuple
from   pprint      import pprint
from   struct      import unpack

import csv
import distutils.spawn
import getopt
import json
import os
import pdb
import re
import string
import struct
import subprocess
import sys

#
# A tiny scrap o sanity... is anything there?
#
commands_to_run = ['bmc-config', 'pef-config', 'ipmi-sensors-config', 'ipmi-chassis-config']
command_paths   = []

for command in commands_to_run:
   command_path = distutils.spawn.find_executable(command)
   if command_path != "":
      command_paths.append(command_path)

if command_paths == []:
    print("couldn't find any of the commands needed to run this program!  This requires:")
    print(commands_to_run)
    exit(1)


verbose = False

# always a tricky one... a minute seems plausible.
# In the spec this is the IPMI session inactivity timeout...?
timeout  = 60

# used for json trees
idnum = 0

opts_s  = "cd:Dhjp:P:r:Rt:u:vV"
usage   = "Usage: %s %s" % (sys.argv[0], opts_s)
version = ".02"

opts, args = getopt.getopt(sys.argv[1:],opts_s)

# not even sure I'll do any other, but at least plant a seed
print_format = "json"

user     = ""
password = ""
debug    = False
raw      = False

# number of times to try a command before giving up
trials  = 1
# number of consecutive timeouts (e.g. 2 queries in a row that have timed out, failed, etc) before we bail
retries = 0

for opt, arg in opts:

#  -a             Prompt for remote password       XXX
   if opt == '-c':
      print_format = "csv"
#  -d N           specify a /dev/ipmiN deve to use (defaults to 0/first)      XXX
   elif opt == '-d':
      dev_num = arg
# -h or --help
   elif opt in ("-h", "--help"):
      print(usage)
      sys.exit(0)
#  -D             debug                            XXX
   elif opt == '-D':
      debug = True
# -j              output JSON
   elif opt == '-j':
      print_format = "json"
#  -P             port                             XXX
   elif opt == '-P':
      port = arg
#  -p             password
   elif opt == '-p':
      password = arg
#  -r             retries
   elif opt == '-r':
      retries = int(arg)
#  -R             port
   elif opt == '-p':
      raw = True
#  -t             timeout
   elif opt == '-t':
      timeout = arg
#  -u             username
   elif opt == '-u':
      user = arg
#  -v             verbose
   elif opt == '-v':
      verbose = True
#  --version/-V             version of this tool
   elif opt in ("-v", "--verbose"):
      print(version)
      sys.exit(0)

# args can be gotten from args['foo']
# args = parser.parse_args()

try:
    target = (args[0])
except:
    print(usage)
    exit(2)

if verbose:
   print("geting data from %s" % target)

#
# all data gets stuffed into here
#
j_schtuff         = defaultdict(list)
j_schtuff[target] = target

master_csv = []

#
# take a byte stream and split it on newlines, output
#

def raw_print(bytes):
   for line in bytes.split('\n'):
      # print(line, end='')
      # print(line)
      print(line)

#
# it's all packaged up... go to town
#
def print_csv():

   print("CSV... not sure how to do this yet ;)")

   # selectric = csv.writer(sys.stdout)
   # selectric.writerow(row)


#
# it's all packaged up... go to town
#
def print_json(data, indent=0):

   # sorted_data = OrderedDict(sorted(data.items(), key=lambda t: t[0]))
   # data["id"]   = "0"

   jdata = json.dumps(data)

   print(jdata)


#
# keep a running tally of what's been going on
#
def stash_results(tool, options,json_out, print_format):

#  json_out = json_out[json_out.keys()]

   if json_out == {}:
      return

   ipmi_out = OrderedDict()

   global idnum

   idnum = idnum + 1

   # want the tool name, not the full path to the tool
   toolname = ''.join(tool.split('/')[-1:])

   if (print_format == "csv"):
      # print("stashing... %s" % json_out)
      master_csv.append(json_out)

   elif (print_format == "json"):
      # j_schtuff[tool] = json_out
      j_schtuff[toolname] = json_out

   else:
      print("... not sure what you want me to output...?")
      exit(1)

#  print("JSTUFF: ")
#  print(j_schtuff)


#
# we're going to be running a lot of commands... so...
#
def run(tool, args):

   out_string = ""
   err_string = ""

   # seems safer using the OS time vs. python's... this is
   # probably only running in linux, so...
   command_string = "timeout %s %s %s" % (timeout, command, args)

   if verbose:
      print("executing %s" % (command_string))

   # unepipe = subprocess.Popen(command_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=i_timeout);
   unepipe = subprocess.Popen(command_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE);

   out = unepipe.stdout.read()
   err = unepipe.stderr.read()

   # not sure I really want to do this ... 
   out_string = out.decode('utf-8')
   err_string = err.decode('utf-8')

   result_file  = "_ipmirun.txt"

   json_out = {}

   # save raw output to a file
   if raw:
      date   = subprocess.check_output(["date"])
      bugrun = open(result_file, "a+b")
      bugrun.write("\n***\n".encode('utf-8'))
      bugrun.write(date)
      bugrun.write("***\n\n".encode('utf-8'))
      bugrun.write(command_string.encode('utf-8'))
      bugrun.write("\n\n".encode('utf-8'))

   if (out_string != ""):
      # return 0, out
      if raw:
         bugrun.write(out)
         bugrun.write("\n".encode('utf-8'))
         bugrun.close()

      json_out = parse_sections(tool, args, out_string)
      stash_results(tool, args, json_out, print_format)

      return 0, json_out

   elif (err_string != ""):
      if verbose:
         print("Failure: command %s, with arguments %s (error: %s)" % (tool, args, err_string))
      if raw:
         bugrun = open(result_file, "a+b")
         bugrun.write(err)
         bugrun.write("\n".encode('utf-8'))
         bugrun.close()

      return(1, err_string)

   else:
      if raw:
        bugrun.write("nothing came out...\n".encode('utf-8'))
        bugrun.close()

      print("... nothing came out at all... was executing %s %s" % (command, args))
      return(1, "")

   #    fillabuster = 1

# parse sections, return a json string that contains the salient output
#
# Sections have a pretty regular format.  Inside a section the lines 
# look like one of 4 things...
#
# 1) starting with a hashsign, with optional leading whitespace.
#    this is a comment - kill those lines for now, 'till I figure...?
#    Looks like:
#
#     # Some motherboards may require a "Username" to be configured prior to other 
#         ## Give Username
# etc.
#
# 2) starting at column 0, starting with "EndSection" + whitespace + name of section
#
#             Section User2
#
#    This starts a section with a given name
#
# 3) starting with a tab and followed by data.  Almost always two fields,
#    but seems to have a few one-word ones, like:
#
#     Admin_Enable_Auth_Type_MD2                    Yes
#     Username                                      
#
#   This is all data within a section
#
# 4) starting with and only containing the word "EndSection" - ends a section,
#    obviously :)
#
def parse_sections(tool, options, data):

   if verbose:
      print("parsing output from %s" % tool)

   j_dict = defaultdict(dict)

   section_title = ""

   # rip over data, one line at a time
   for line in data.splitlines():

      line = line.rstrip()

      if debug:
        print("line:\t %s" % line)

      # blank line, reset things
      if line == "":
         if debug:
            print("\n\n <- skipping blank line -> \n\n")
         continue

      # where does the line start, and what does it start with?
      column_start = len(line) - len(line.lstrip())
      char_start   = line[column_start:column_start+1]

      line = line.strip()

      # print("LN:%s: => col_strt:%s:\tchar_st:%s:" % (line, column_start, char_start))

      # any comments for the press?
      if char_start == "#":
         if debug:
            print("\tcomment, skipping: %s" % line)
         continue

      # 1-2 things on line
      try:
        one, two = line.split()
      except:
        if debug:
            print("\tthere can be only one....")
        one = line
        two = ""

      if debug:
        print("one/two:%s:%s" % (one,two))

      # something at the zero
      if not column_start:
         # start of something new
         if one == "Section":
            section_title = two
            if debug:
               print("\n\tnew section: %s" % section_title)

            j_dict[section_title] = {}

         # end of something old
         elif one == "EndSection":
            section_title = ""
            two = ""
            if debug:
               print("\\ttend o' a section: %s" % section_title)

         # who knows?
         else:
            print("WTF?")

         continue

      if section_title == "":
         print("you failed the sanity check")
         continue

      # ' '.join(the_string.split())

      j_dict[section_title][one] = two

      one = ""
      two = ""

   return(j_dict)

#
#
# Start the big show
#
#

# options    = " -v -u %s -p %s -h %s --checkout" % (user, password, target)
target_opt = "-h %s" % target

if user != "" and password != "":
    options = " -v -u %s -p %s %s --checkout" % (user, password, target_opt)
else:
    options = " -v %s --checkout" % target_opt
    # print("I said the socket, not sprocket, wrench! Bailin' with %s and %s", (Exception, e))
    
# overall
total_failures = 0

#
# prepare for the flood
#
for command in command_paths:

    if verbose:
        print("... running command %s" % command)

    # per command
    command_failures = 0

    for n in range(trials):

       # run the command, get results
       ret, ret_data = run(command, options)

       if debug:
          print ("Returned:%s:Data:%s:" % (ret, ret_data))

       # failure
       if ret:
          print("failure: \'%s %s\'" % (command, options))
          command_failures += 1
          total_failures   += 1

          # total fails
          if total_failures > retries:
             print("Total commands failed = %s (maximum allowed is %s), giving up" % (total_failures, retries))
             exit(1)

          # this command fails
          if command_failures > trials:
             print("command failed %s times, giving up on command c(maximum allowable retries is %s)" % (command_failures, trials))
             exit(1)
       else:
          # print(ret_data)
          break

#
# dump all the schtuff
#
print_json(j_schtuff)

