#!/usr/bin/perl

#
# post process IPMI scan from jonah stage 1... scoring systems to
# see how IPMI-ish they look.  The higher the score, the more likely
# they are running IPMI, even if you can't talk to it directly.
#

#
# How to use:
#
# This requires a file from stage one with appropriate output: simply:
#
#        $0.pl [options] target
#
#
# Options:
#
# -h/-help           print how to use tool stuff & exit
#
# -t                 terse; just score and host
#
# -v verbose
#
# -version           print version number & exit
#

#
# drag in some stuff
#
# do vendor first, then weights
#
@config_files = ("j_vendor.pl", "j_weights.pl");

use Getopt::Long qw(:config no_ignore_case);

#
# process command line arg stuff
#

sub main::VERSION_MESSAGE {
   print "$1 0.0.2\n";
   exit;
};

sub main::HELP_MESSAGE {
   print "Usage: $0 [options] results-file\n".
   "\t-h/help\t\t\t\tPrint help text and exit\n".
   "\t-t\t\t\t\tTerse - just print score and host\n".
   "\t-v\t\t\t\tVerbose\n".
   "\t-version\t\t\tPrint version #\n";
   "\t-V\t\tdon't do any vendor specific tests\n".
   exit;
};


GetOptions(
   'c'       => \$csv,
   'csv'     => \$csv,
   'h'       => \$help,
   'help'    => \$help,
   't'       => \$terse,
   'v'       => \$verbose,
   'V'       => \$vendors,
   'version' => \$version
) || die main::HELP_MESSAGE();

if (defined($help))    { die main::HELP_MESSAGE(); }
if (defined($version)) { die "version .01\n"; }
if (defined($verbose)) { $verbose = 1; }
if (defined($terse))   { $terse   = 1; }
if (defined($csv))     {
   die "not implemented, sorry...\n";
   $csv         = 1;
}

#
# by default do all vendor checks when reporting
#
$ALL_vendors = 1;
if (defined($vendors)) { $ALL_vendors = 0; }

#
# rip apart the results file... hunting for signs of IPMI
#
$file_suffix  = $ARGV[0];

die "requires a results file to process\n" unless $file_suffix ne "";

$results_nmap = "$file_suffix.nmap.txt";

die "requires a results file to process; $results_nmap not found\n" unless -f $results_nmap;

#
# putting this separate for now, for easier editing
#

# two files - one to suck in the weights to apply to the findings,
# one to get the various vendor bits pulled in

# require, do, use, eval... try do for now ;)
# do "j_weights.pl";
# $file = "j_vendor.pl";
# do "j_vendor.pl";

# ($all_IPMI_udp_ports, $all_IPMI_tcp_ports, %all_vendor_ports) = vendorish();
for $file (@config_files) {
   print "reading in $file\n" if $verbose;
   unless ($return = do $file) {
      die "couldn't parse $file: $@" if $@;
      die "couldn't do $file: $!"    unless defined $return;
      die "couldn't run $file"       unless $return;
   }
}

#
# see if there's an ipmi-ping file, and, if so, process
#

$results_ipmi = "$file_suffix.ipmi.txt";

if (-s $results_ipmi) {
   print "opening $results_ipmi for parsing\n" if $verbose;
   open(IPMI_RES, $results_ipmi) || die "couldn't open ipmiping results file $results_ipmi\n";

   while (<IPMI_RES>) {
      chomp();
      # looks like.... Successful ipmi-ping: response received from 10.10.10.10: rq_seq=16, auth: none=clear md2=set md5=set password=set oem=clear anon=clear null=set non-null=set user=clear permsg=clear 

      #
      # ipmiping returns an IP address on the success line even if
      # a hostname was specified... have to think about this
      #
      if (/Successful ipmi-ping/) {
         print "Successful i-ping: $_\n" if $verbose;
         /^.*Successful ipmi-ping: response received from (\S+): (.*)$/;
         $ipmi_hosts{$1}   = $1;
         $ipmi_options{$1} = $2;
         print "IPMI-results: $ipmi_hosts{$1} => $ipmi_options{$1}\n" if $verbose;
      }
   }
   close(IPMI_RES);
}

print "opening $results_nmap for parsing\n" if $verbose;

open(NMAP_RES, $results_nmap) || die "can't read nmap results file: $results_nmap\n";

# running score of IPMI-ness of a given host
$host_i_score          = 0;

# various other state/status/tmp vars
$start_sucking_fingers = 0;
$current_host          = "";
%i_reason              = {};
%i_vendor              = {};
$alive                 = 0;
$bmatch                = 0;

while (<NMAP_RES>) {

   # if we're sucking in fingerprints we're looking for a blank line
   # to return to normal... but if we happen to see IPMI... well...
   if ($alive && $start_sucking_fingers) {

      if (/IPMI/i) {
         print "found IPMI string while sucking on fingers...\n" if $verbose;
         $host_i_score += $i_sucking_fingers;
         $i_reason{$current_host} .= "suck match/";
      }

      if (/^\s*$/) {
         print "stop the suck\n" if $verbose;
         $start_sucking_fingers = 0;
      }
   print "s.." if $verbose;
   next;
   }

   # skip comments & blanks
   next if (/^#/ || /^\s*$/);

   # skip OS detail/guesswork things
   next if (/^OS / || /^OS:/);

   chomp;

   $port=$proto=$state=$service=$xtra="";

   #
   # if on the line, get the host... so when we get to various results we'll know where
   # to apply the results to
   #
   if (/Nmap scan report for/) {
      print "\nhost $current_host...\n" if $current_host ne "" && $verbose;

      if ($current_host ne "") {

         if ($host_i_score) {
            # print "$host_i_score = i-score for $current_host ($i_reason{$current_host})\n" if $host_i_score;
            print_i_score();
         }

      }

      #
      # the identiy line looks like...
      #
      # no hostname:
      #
      #     Nmap scan report for 10.0.0.1
      #
      # or, with hostname:
      #
      #     Nmap scan report for rawrr (10.0.0.1)
      #

      $host_i_score            = 0;

      # courtesy of http://stackoverflow.com/questions/106179/regular-expression-to-match-hostname-or-ip-address
      $ip_regexp = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])";
      m/Nmap scan report for (\S+)\s\(($ip_regexp)\).*$/;

      if ($2 eq "") {
         m/Nmap scan report for (\S+).*$/;
         $current_host    = $1;
         $current_full_ID = $current_host;
         $current_rdns    = "";
      }
      else {
         $current_host    = $1;
         $current_rdns    = $2;
         $current_full_ID = "$current_host/$current_rdns";
      }

      print "CFID: $current_full_ID ($current_host/$current_rdns)\n" if $verbose;


      if (/\[host down\]/) {
         $host_state{$current_host} = "down";
         $alive = "0";
      }
      else {
         $host_state{$current_host} = "up";
         print "\nhost $current_host is $host_state{$current_host}\n" if $verbose;
         $alive = "1";
      }
      # print "host $current_host is $host_state{$current_host}\n";
   }
   elsif (/Scanned at/ || /PORT.*STATE.*SERVICE.*VERSION/ || /is up\s*$"/) {
      next;
   }
   #
   # next look for ports open/closed/etc.  Lines look like:
   #
   # 443/tcp   closed https   
   #
   elsif (/^\d+\/\S+\s+\S+\s+\S+\s+\S+/) {
      # print "L: $_\n";

      if    (/(tcp|udp)\s+open / && !/tcpwrapped/) {
         m/^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/;
         $portproto = $1;
         $state     = $2;
         $service   = $3;
         $reason    = $4;
         $xtra      = $5;

         #
         # if the final field has anything in it, look for clues....
         #
         if ($xtra eq "") {
            # print "... going to plan B...\n";
            ($portproto, $state, $service, $reason) = split(/\s+/);
         }
         else {

            # err.... mini dr. banner, I presume
            # print "\n\tsmall hulk? $xtra\n";

            # does it match any of the magic ones?
            # print "\n... checking for...\n";
            for $i_banner (keys %ipmi_banners) {
               # print "\t$xtra =~ m/$i_banner/?\n";
               if ($xtra =~ m/$i_banner/) {
                  print "\n\tmini-banner match!  $i_banner =~ $xtra; adding $ipmi_banners{$i_banner} to $host_i_score ($portproto)" if $verbose;
                  $host_i_score += $ipmi_banners{$i_banner};

                  # $i_reason{$current_host} .= "B:$i_banner/";
                  # i_add_reason($current_host, 'banner', $i_banner);
                  i_add_reason($current_host, 'banner', $xtra, $i_banner);

                  $bmatch = 1;

                  # can we match this with a vendor?
                  if (defined($vendor_banners{$i_banner})){
                     print "\tvendor match: $vendor_banners{$i_banner}\n" if $verbose;
                     $i_vendor{$vendor_banners{$i_banner}} += $ipmi_banners{$i_banner};
                  }

                  last; # can only match once per line ;)
               }
            }
         }

         # looks like 443/tcp, separate the siamese twins
         ($port, $proto) = split(/\//, $portproto);

      }
      elsif (/(tcp|udp)\s+closed(|\|filtered)/ || /(tcp|udp)\s+open(|\|filtered)/ ||
             /(tcp|udp)\s+filtered/ || /(tcp|udp)\s+\S+\s+(ssl\/|)tcpwrapped/) {

         ($portproto, $state, $service, $reason) = split(/\s+/);

         # print "\nSVC ($_): $service\n";

         # unsure ....
         $state = "tcpwrapped" if (/tcpwrapped/);

         ($port, $proto) = split(/\//, $portproto);
      }
      else {
         die "woah... don't know how to deal with this one...$_\n";
      }

      # if closed, don't bother
      if ($state ne "closed") {
         print "\nPortProtoStateSvc: $port, $proto, $state, $service, $xtra\n" if $verbose;
      }


      #
      # don't count both udp & tcp for the same port
      #
      next if defined($ports_counted{$current_host}{$port});
      $ports_counted{$current_host}{$port}++;

      #
      # port analysis... does this port matter at all to IPMI?
      #
      # if closed, don't bother
      if ($state ne "closed") {

         print "\tport: $port => $all_vendor_ports{$port}{$proto} weight...\t" if $verbose;

         # need to add weight unless you want it treated like dogmeat
         if (!defined($weight_port{$proto}{$port})) {
            # print "\n... warning... I don't know $port/$proto\'s weight... asssigning it \$weight_unknown value ($weight_common)\n" if $verbose;
            # for this run treat it like any other port
            $weight_port{$proto}{$port} = $weight_common;

         }

         if (defined($weight_state{$state})) {
            # if zero weight don't count it
            if (!$weight_port{$proto}{$port}) {
               print " zero weight for $port" if $verbose;
            }
            else {
               print "add $weight_state{$state} * $weight_port{$proto}{$port} to $host_i_score" if $verbose;
               $host_i_score += $weight_state{$state} * $weight_port{$proto}{$port};

               $suffix = "";
               if    ($proto eq "tcp") { $suffix = "t-"; }
               elsif ($proto eq "udp") { $suffix = "u-"; }
               else  { die "don't know how to deal with proto:$proto:\n"; }


               if    ($state eq "open")            { $suffix .= "o";  }
               elsif ($state eq "filtered")        { $suffix .= "f";  }
               elsif ($state eq "tcpwrapped")      { $suffix .= "t";  }
               elsif ($state eq "open|filtered")   { $suffix .= "of"; }
               elsif ($state eq "closed|filtered") { $suffix .= "cf"; }
               else {
                  die "hmm, don't know this state... $state\n";
               }

               # $i_reason{$current_host} .= "$port$suffix/";
               i_add_reason($current_host, 'port', $port, $proto, $state);

               # any vendors stand out?
               for $vendor (keys %all_vendors) {
                  # don't track generic!
                  next if ($vendor eq "generic");
                  if (defined($ports_n_vendors{$vendor}{$proto}{$port})){
                     # print "adding ... to $current_host from $vendor\n";
                     $i_vendor{$vendor} += $weight_state{$state} * $weight_port{$proto}{$port};
                  }
               }

            }
         }
         else {
            print "...\n\n... don't know this state? $state\n";
         }
      }
   }

   elsif (/^Running:/) {
      /^Running: (.*$)/;
      $os = $1;
      # print "OS: $os\n";
   }
   elsif (/^Aggressive OS guesses:/) {
      /^Aggressive OS guesses: (.*$)/;
      $os = $1;
      # print "OS (aggressive): $os\n";
   }
   elsif (/^Running \(Just GUESSING\):/) {
      /^Running \(Just GUESSING\): (.*$)/;
      $os = $1;
      # print "OS (guessing): $os\n";
   }
   elsif (/^No exact OS matches:/) {
      # print "OS: unknown\n";
   }
   elsif (/^No OS matches/) {
      # print "OS: unknown\n";
   }

   # just throw away fingerprint data... unless it has IPMI...!
   elsif (/unrecognized despite returning data/) {
      print "starting to suck down useless fingerprints\n" if $verbose;
      $start_sucking_fingers = 1;
   }

   # :   |_banner: SSH-2.0-OpenSSH_5.2
   elsif (/|_banner/) {
      ($x, $hulk) = split(/:/);

      # err.... dr banner, I presume
      # print "\tHulking banner: $hulk\n";

      if ($hulk ne "") {

         $hulk = "\Q$hulk\E";

         # does it match any of the magic ones?
         for $i_banner (keys %ipmi_banners) {

            last if $bmatch;

            # print "BANNER?  $hulk =~ /$i_banner/ ($vendor/$proto/$port)\n";
            if ($hulk =~ /$i_banner/) {
               print "BANNER MATCH!  $i_banner =~ $hulk; adding $ipmi_banners{$i_banner} to $host_i_score\n" if $verbose;
               $host_i_score += $ipmi_banners{$i_banner};

               # $i_reason{$current_host} .= "B:$i_banner/";
               i_add_reason($current_host, 'banner', $hulk, $i_banner);

               #
               # any vendors stand out?
               #
               if (defined($vendor_banners{$i_banner})){
                  print "\tvendor match: $vendor_banners{$i_banner}\n" if $verbose;
                  $i_vendor{$vendor_banners{$i_banner}} += $ipmi_banners{$i_banner};
               }

               # can only match once per line!
               $bmatch = 1;
            }
         }
      }
   }
   else {
      print "... uh oh...\n:\t$_\n";
   }

}
close(NMAP_RES);

# last host
if ($current_host ne "") {
   print "\n" if $verbose;
   print_i_score();
}

#
# any vendor stand out as a possible match?
#
# print the one who weighs the most, as per matching, etc
#
sub vendor_possibles {
local($max, $max_v, $max_vv);

   return unless $host_i_score;

   $max    = 0;
   $max_v  = "";
   $max_vv = "";
   for $v (keys %i_vendor) {

      next unless (defined($i_vendor{$v}));

      if ($i_vendor{$v} > $max) {
         $max = $i_vendor{$v};
         $max_v = $v;
      }
      if ($i_vendor{$v} == $max && $max_v ne $v) {
         $max_v .= ":$v";
      }

      $max_vv .= "$v/$i_vendor{$v} ";
   }

   if ($csv) {
      print ",$max,$max_v";
      # if ($verbose) {
      #    print ",$max_vv";
      # }
      print "\n";
   }
   else {
      print "\t$max\t$max_v";
      if ($verbose) {
         print "\t(all): $max_vv";
      }
      print "\n";
   }

   undef(%i_vendor);

}

#
# depending on how I want to output things, save it in various ways
#
sub i_add_reason {
local($host, $reason, @the_rest) = @_;
local($banner, $banner_txt, $banner_score, $csv_bits, $port, $proto, $state, @details, %portx, @banz, @porty);

   print ", adding to reasons for $host\n" if $verbose;

   if ($reason eq "banner") {

      $banner       = pop(@the_rest);
      $banner_txt   = pop(@the_rest);
      $banner_score = $ipmi_banners{$banner};

      # plaintext method
      $i_reason{$host} .= "B:$banner/";

      # more break-out-able details
      if (defined($i_reason_banner{$host})) {
         (@banz) = @{$i_reason_banner{$host}};
      }

      print "adding bannerz ($banner_txt=>$banner_score) to $host\n" if $verbose;

      push(@banz, "$banner_txt:$banner_score");
      $i_reason_banner{$host} = [ @banz ];

   }
   elsif ($reason eq "port") {
      # old method
      ($port, $proto, $state) = @the_rest;
      $portx{"$port,$proto"} = $state;
      $i_reason{$current_host} .= "$proto:$port:$state/";

      # breakoutable....
      if (defined($i_reason_port{$host})) {
         (@porty) = @{$i_reason_port{$host}};
      }

      print "adding ($proto:$port:$state) to $host\n" if $verbose;

      push(@porty, "$proto:$port:$state");
      $i_reason_port{$host} = [ @porty ];

   }
   else {
      die "don't understand reason $reason\n";
   }

}


#
# cough up a CSV hairball
#
sub print_csv {
local($csv_line, @os, @banz, @portz, $status);

   die "not implemented...\n";

   # print "printing up some $host csv, baby\n" if $verbose;

   #
   # OS first
   #
   if ($os ne "") {
	   $csv_line = Text::CSV->new();

      push(@os, $os);
	   $status = $csv_line->combine (@os);

      if (!$status) {
	      die "died: " . $csv_line->error_diag() . "\non:\n\t" . $csv_line->error_input . "\n";
      }
	   print $csv_line->string();
   }
   else {
      #
   }
   print ",";

   #
   # ipmiping-able?
   #
   if (defined($ipmi_hosts{$current_host}) ||
      defined($ipmi_hosts{$current_rdns})) {
      print "yes,";
   }
   else {
      print "no,";
   }

   $os = "OS=?" if ($os eq "");

	if (defined($i_reason_port{$current_host})) {

	   $csv_line = Text::CSV->new();

	   (@portz) = @{$i_reason_port{$current_host}};
      # csv-ify it
	   $status = $csv_line->combine (@portz);
	
	   if (!$status) {
	      die "died: " . $csv_line->error_diag() . "\non:\n\t" . $csv_line->error_input . "\n";
	   }
	   print $csv_line->string();
	}
   else {
      print ",\"\"";
   }

	if (defined($i_reason_banner{$current_host})) {
	   $csv_line = Text::CSV->new();

	   (@banz) = @{$i_reason_banner{$current_host}};

      # csv-ify it
	   $status = $csv_line->combine (@banz);
	
	   if (!$status) {
	      die "died: " . $csv_line->error_diag() . "\non:\n\t" . $csv_line->error_input . "\n";
	   }
	   print "," . $csv_line->string();
	}
   else {
      print ",\"\"";
   }

}

#
# print out the host and results
#
sub print_i_score {
local($ping);

   if (defined($ipmi_hosts{$current_host}) ||
      defined($ipmi_hosts{$current_rdns})) {
      $host_i_score += $ipmi_ping_success;
   }

   $os = "OS=?" if ($os eq "");

   if ($csv) {
      if ($terse) {
         print "$host_i_score, $current_full_ID\n";
      }
      else {
         print "$host_i_score, $current_full_ID,";
         print_csv();
      }
   }
   else {
      if ($terse) {
         print "$host_i_score $current_full_ID\n";
      }
      else {
         if (defined($ipmi_hosts{$current_host}) ||
            defined($ipmi_hosts{$current_rdns})) {
            $ping = "yes";
         }
         else {
            $ping = "no";
         }

         print "$host_i_score = i-score for $current_full_ID ($os, $ping, $i_reason{$current_host})";
      }
   }

   $bmatch = 0;
   $os     = "";

   #
   # any vendors stand out?
   #
   vendor_possibles() if !$terse;;

}
