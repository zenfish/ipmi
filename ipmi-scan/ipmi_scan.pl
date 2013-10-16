#!/usr/bin/perl

#
# Network scan that looks for signs of systems running IPMI.
#

#
# Written by dan farmer/zen@trouble.org.
#
# Not that its ever stopped anyone before from using my stuff (ahem... yes,
# that's you all scan vendors... forensic companies... audit tools... OS
# vendors... but, w/e.) All rights reserved, code preserved, patents applied 
# for, trademarks ensuing, lawyers waitin, mercenaries armed, weapons locked 
# and loaded....
#
# Well, at least some of the above is true.  But as you know, all coders are liars.
#
# Hmm.  Need guns.  Lots more guns.
#

#
# Requires nmap and ipmitools.
#
# Either run as root or have nmap SUID root.
#

#
# How to use:
#
#     At the minimum, give a target type that nmap understands...
#     that is a huge range of things going from individual hosts
#     to wildcards to CIDRs and so on, but at the simplest an
#     IP address or hostname. So:
#
#        $0.pl [options] target
#
# Options:
#
# -A                          Scan with all the vendor options set.  If used
#                             I'll ignore the -V options
#
# -f file                     read the targets from a file
#
# -h/-help                    print how to use tool stuff & exit
#
# -I /path/to/ipmitool        if you want to use a specific ipmitool binary, path here
#
# -N /path/to/nmap            if you want to use a specific nmap binary, , path here
#
# -O value                    for OS scanning... values can be either "yes" or "high";
#                             high simply does more aggressive scanning.
#                             Defaults to not scanning OS... but maybe should change this.
#
# --tcp                       enable TCP port scanning
# --udp                       enable UDP port scanning
#
#                             UDP scanning makes paint drying look fun.  If you
#                             specify both of these there will be no change; both
#                             udp & tcp will run.  Specifying only one of them says
#                             scan that proto's ports; let me assure you under normal
#                             circumstances --tcp will speed things up, but you won't
#                             see the UDP stuff... this may or may not matter, depending
#                             on what you're looking for, doing, etc.
#
# -v verbose
#
# -V vendor foo,bar,baz       comma sep'd vendors (don't fuck with me and put
#                             commas in a vendor or I'll parse you wrong out
#                             of spite).  Could split this further into tcp/udp,
#                             but for now....
#
# -version                    print version number & exit
#

#
# Thoughts/notes
#
# -O/OS option... might want to do an OS scan and then go back and scan with
# the appropriate opts, or make a better analysis of the target... hopefully
# with data gathered and more experience this will become clearer as to
# what to do.
#
#

#
# a few key vars for use down below
#

#
# pretty much always this... certainly for starters!
#
$IPMI_PORT = 623;

# number of IPMI ping attempts to send
$IPMI_PING_ATTEMPTS = 2;

#
# includes... need these... builtin, shouldn't be an issue unless things are whacked
#
use Getopt::Long qw(:config no_ignore_case);

# this runs as root or SUID... chmod it for now, figure out what to do later
umask 000;

#
# process command line arg stuff
#

# nifty new (probably over a decade old, I hadn't known ;)) perly bits
sub main::VERSION_MESSAGE {
   print "$1 0.0.1\n";
   exit;
};

sub main::HELP_MESSAGE {
   print "Usage: $0 [options] target\n".
   "\t-A\t\t\tScan with all vendor specific tests on... will ignore -V flag if set.\n".
   "\t-f file\t\t\t\tRead the targets from a file\n".
   "\t-h/help\t\t\t\tPrint help text and exit\n".
   "\t-I /path/to/ipmitool\t\tUse a specific verion of ipmitool\n".
   "\t-N /path/to/nmap\t\tUse a specific verion of nmap\n".
   "\t-O yes|high\t\tOS scanning: do it (yes) or do it agressively (high)\n".
   "\t-tcp\t\t\t\tOnly do TCP scans... unles -udp is also given\n".
   "\t-udp\t\t\t\tOnly do UDP scans... unles -tcp is also given\n".
   "\t-v\t\t\t\tVerbose\n".
   "\t-V vendor1,v2,v3\t\tVendor specific tests; one+ comma sep'd vendor names\n".
   "\t-version\t\t\tPrint version #\n";
   exit;
};

GetOptions(
   'A'       => \$ALL_vendors,
   'f=s'     => \$file,
   'h'       => \$help,
   'help'    => \$help,
   'I=s'     => \$ipmitool,
   'N=s'     => \$nmap,
   'O=s'     => \$OS_scan,
   'tcp'     => \$scan_tcp,
   'udp'     => \$scan_udp,
   'v'       => \$verbose,
   'V=s'     => \$vendors,
   'version' => \$version
) || die main::HELP_MESSAGE();

if (defined($verbose))     { $verbose     = 1; }
if (defined($ALL_vendors)) { $ALL_vendors = 1; }
if (defined($scan_tcp))    { $scan_tcp    = 1; }
if (defined($scan_udp))    { $scan_udp    = 1; }

#
# -tcp & -udp flags can cancel each other out
#
if ($scan_tcp && $scan_udp) {
   $scan_tcp = $scan_udp = 0;
}


#
# who are the lucky few?
#
if ($file eq "") {
   $targets = join(" ", @ARGV);
}
else {
   $targets = "-iL $file";
}

die main::HELP_MESSAGE() unless $targets ne "";

print "Targets are $targets\n" if $verbose;

#
# Nmap results written to file:     $target + .txt
# ipmiping results written to file: $target + .ipmi
#

# strip /'s so I can write to the file (e.g. 10/8 => 10_8)
($tmp_tar = $targets) =~ s@/@_@g;
$tmp_tar = $file if $file ne "";

$results_nmap = "$tmp_tar.nmap.txt";
$results_ipmi = "$tmp_tar.ipmi.txt";

# truncate in case of previous results
open(IPMI_RES, "> $results_ipmi") || die "can't open $results_ipmi file for ipmiping results\n";
close(IPMI_RES);

#
#
# Find tools required (currently nmap & ipmitool), do permission checks
#
#
@toolz = ('nmap', 'ipmitool');
#
# toolname = 1/0: 1 means must be SUID, 0 just executable
#
%toolz = (
   'nmap', 1,
   'ipmitool', 0,
   'ipmiping', 0
);

# if system binaries won't work, point to your private stash
if (defined($opts{I})) { $tool_location{'ipmitool'} = $opts{I}; }
else                   { $tool_location{'ipmitool'} = "ipmitool"; }
if (defined($opts{N})) { $tool_location{'nmap'}     = $opts{N}; }
else                   { $tool_location{'nmap'}     = "nmap"; }
$tool_location{'ipmiping'} = "ipmiping";

# not sure what to do... probably won't require ipmiping; for now just
# pass over it if can't find it
$ipmiping = 0;

# for $tool (@toolz) {

for $tool (keys %toolz) {

   # print "T: $tool => " . $toolz{$tool} . "\n";

   next if ($tool eq "");

   # yeah or nay?
   $suid = $toolz{$tool};

   # out there anywhere?
   print "which $tool_location{$tool}\n" if $verbose;

   chomp($tool_location{$tool} = `which $tool_location{$tool}`);

   print "looking for $tool...\n" if $verbose;

   if ($tool_location{$tool} eq "") {
      if ($tool eq "ipmiping") {
         print "couldn't find ipmiping, tool won't be as accurate without...\n";
         $tool_location{$tool} = "ipmiping";
         $ipmiping = 1;
      }
      else {
         die "\t$0 requires $tool to run\n";
      }
   }
   else {
      print "\tfound $tool_location{$tool}\n" if $verbose;
   }

   if ($suid) {
      # gotta laugh at perl somtimes....
      $euid = $<;

      # euid = 0 = root
      if ($euid) {
         # check for SUID 
         die "Must run $tool_location{$tool} as root or have $tool SUID\n" unless -u $tool_location{$tool};
      }
   }

   if (! -x $tool_location{$tool} && ! $ipmiping) {
      die "$tool_location{$tool} isn't executable ($ipmiping)\n";
   }

}

#
# figure out how to do this ;)
#
# require "j_vendor.pl";
$file = "j_vendor.pl";
unless ($return = do $file) {
   die "couldn't parse $file: $@" if $@;
   die "couldn't do $file: $!"    unless defined $return;
   die "couldn't run $file"       unless $return;
}

# ($all_IPMI_udp_ports, $all_IPMI_tcp_ports, $all_vendor_ports) = vendorish();

#
#
# Finally... first, we run nmap with the ports constructed above against the
# targets specified.
#
#

#
# NMAP
# NMAP below
# NMAP
#

#
# construct nmap's options... when doing both UDP/TCP, nmap requires a small bit of 
# trickery; the T/U flags on the ports to distinguish between U/T
#

$udp_opts  = "";
$tcp_opts  = "";
$all_ports = "-p ";

if ($all_IPMI_udp_ports ne "") {
   $udp_opts    = "-sU";
   $all_ports .= "U:$all_IPMI_udp_ports";
}

if ($all_IPMI_tcp_ports ne "") {
   #
   # default nmap scan... we'll use it for now, but have to specify
   # when doing tcp+udp simultaneously
   #
   $tcp_opts = "-sS";
   # put a comma between if both
   if ($all_IPMI_udp_ports ne "") {
      $all_ports .= ",";
   }
   $all_ports .= "T:$all_IPMI_tcp_ports";
}

#
# from the nmap docs:
#
#  OS DETECTION:
#  -O: Enable OS detection
#  --osscan-guess: Guess OS more aggressively
#
# parse the -O option to figure out what to do
#
if (defined($OS_scan)) {
   if    ($OS_scan eq "yes") {
      $OS_opts = "-O";
   }
   elsif ($OS_scan eq "high") {
      $OS_opts = "--osscan-guess";
   }
   else {
      die "unknown value for -O: $OS_scan\n";
   }
}
else {
   $OS_opts = "";
}

print "OS scan options to be passed to nmap are \"$OS_opts\"\n" if $verbose;

# 
# Nmap options; from nmap:
#
# -sV: Probe open ports to determine service/version info
# --script=banner: uses an nmap NSE script to dump out more data on banners found
#
$nmap_options = "-vvv --reason -T4 -sV --script=banner $OS_opts ";

# verbose might be required, I think, to do real-timish processing to
# speed things along
$nmap_options .= "$udp_opts $tcp_opts $all_ports -v";

# for testing... output to file
$nmap_options = "-oN $results_nmap $nmap_options";

$nmap_exe     = "$tool_location{'nmap'} $nmap_options $targets";

print "\nRunning $nmap_exe \n\n" if $verbose;

# if ($fooooo) {

open(NMAP_EXE, "$nmap_exe |") || die "can't run $nmap_exe\n";

while (<NMAP_EXE>) {

   print $_;

   # if see any open TCP/UDP 623s/IPMI_PORT, hit again with ipmtool
   # to see if it's really ipmi/alive
   if (/Discovered open port $IPMI_PORT\/..p on/) {

      if (!defined($ipmi_ping_results{$target})) {
         print "... checking...\n";
         m/Discovered open port $IPMI_PORT\/(..p) on (.*)$/;
         $proto  = $1;
         $target = $2;
         # print "forking off $1 ipmi scan vs. $2\n" if $verbose;

         print "forking off $proto ipmi scan vs. $target\n";

         #
         # ipmitool
         # ipmitool run in function below
         # ipmitool
         #
         if (!ipmi_ping($target, $proto)) {
            $ipmi_ping_results{$target} = 1;
         }
         else {
            $ipmi_ping_results{$target} = 0;
         }
      }
   }

}

close(NMAP_EXE);

#
# A little sub that uses ipmiping to determine if a host is up or
# down, IPMI-wise.  Send two tries (this is UDP, after all, try
# to be a bit safer; 1 too few, 3+ too many?), although may send 
# more/less as I learn more....
#
# looks something like this when run:
#
# Non-IPMI:
#
#     # ipmiping -c 1 -v 192.168.0.55
#     ipmiping 192.168.0.55 (192.168.0.55)
#     response timed out: rq_seq=56
#     --- ipmiping 192.168.0.55 statistics ---
#     1 requests transmitted, 0 responses received in time, 100.0% packet loss
#
# IPMI host:
#
#     # ipmiping -c 1 -v 192.168.0.69
#     ipmiping 192.168.0.69 (192.168.0.69)
#     response received from 192.168.0.69: rq_seq=20, auth: none=clear md2=set md5=set password=clear oem=set anon=clear null=clear non-null=set user=clear permsg=clear 
#     --- ipmiping 192.168.0.69 statistics ---
#
sub ipmi_ping {
   local($target, $proto) = @_;

   print "off to i-ping with ipmiping $target\n" if $verbose;

   if ($ipmpiping) {
      print "... oops, I take that back... ipmiping wasn't found, remember?\n"  if $verbose;
      return 6;
   }

   open(IPMI_RES, "> $results_ipmi") || die "can't open $results_ipmi file for ipmiping results\n";

	$valid_stuff  = "[a-zA-Z0-9\.\-]";
	
	#
	# only allow letters, numbers, and a few diff types chars for a target
	# (should be simple IP or hostname)
	#
   if ($target !~ /$valid_stuff/) {
	   print "weirdy chars in target2 ($target)!\n" if $verbose;
	   return 1;
   }

	# damn the torpedos, pingify that sucker, Ms. Sulu!
	# print "ipmiping -c 1 -v $target |\n";
	print "\nrunning: ipmiping -c 1 -v $target \|\n" if $verbose;
	open(IPING, "ipmiping -c 1 -v $target |") || die "can't run ipmiping against $target\n";
	
	#
	# expecting something like (all one line):
	#
	#      response received from 192.168.0.69: rq_seq=20, auth: none=clear \
	#      md2=set md5=set password=clear oem=set anon=clear null=clear \
	#      non-null=set user=clear permsg=clear 
	#
	#  For now just throw away results, looking for that magic response line... I'll be
	# ripping into this more later, or perhaps doing it here... haven't decided yet....
	#
	$success = "";
	while (($_iping = <IPING>)) {
      # print "KKK: $_iping";
      chomp($_iping);
	   if ($_iping =~ /response received/) {
	      $success = $_iping;
	   }
	}
	close(IPING);

   if ($success ne "") {
	   print          "Successful ipmi-ping: $success\n" if $verbose;
	   print IPMI_RES "Successful ipmi-ping: $success\n";
   }
   else {
	   print          "ipmi-ping failed\n" if $verbose;
	   print IPMI_RES "ipmi-ping failed\n";
   }

   close(IPMI_RES);

	return 0;

}
