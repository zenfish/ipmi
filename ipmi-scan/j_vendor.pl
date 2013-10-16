
#
# some share stuff... define vendor stuff here for both scanning and
# interpretation
#

#
#
# vendor specifics
#
#

#
# Minor note: I'm not worried about duplicate ports, nmap will take care of them in the end
# (yes, I'm a slacker.)
#

# UDP
$IPMI_PORT  = 623;

# this is an interesting one... enough evidence seems to exist to merit a trial, at least
# UDP
$IPMI_PORT2 = 624;

#
# the only real port is 623... but the others have useful things to look for...
#
# 69          = tftp
# 161         = SNMP
# 161         = SNMP trap
# 5900/5901   = vnc
#
$vendor_udp_ports{"generic"}    = "$IPMI_PORT,$IPMI_PORT2,69,161,162,5900,5901";

#
# 22          = ssh
# 23          = telnet
# 161         = SNMP
# 161         = SNMP trap
# 5900/5901   = vnc
# 80,443,8080 = web
#
$vendor_tcp_ports{"generic"}    = "22,23,80,161,162,443,$IPMI_PORT,5900,5901,8080";

#
# Dell 
#
# Some info in "DellTM OpenManageTM Version 5.2 Installation and Security User's Guide",
# pretty similar at:
#
#     http://support.euro.dell.com/support/edocs/software/smsom/5.4/en/ug/HTML/security.htm
#
# Which shows 3 billion ports (plus or minus ;)) used
#

#
# from:
#
#     http://support.dell.com/support/edocs/software/smsom/4.4/en/ug/security.htm
#
# for DRAC III, DRAC III/XT, 4 ...
#
# 2068 Video Redirection - Keyboard/Mouse (digital KVM)
# 3668 Virtual Media server
# 3269 global catalog (GC) port (common)
# 3668 Virtual Media Service - iDRAC 5+
# 3669 Virtual Media Service + SSL - iDRAC 5+
# 5869 Remote racadm CLI utility (cleartext!)
# 5981 VNC
# 8192 Video redirection to client viewer
#
$vendor_udp_ports{"Dell"}       = "1278,1279,2606,2607,4995"; 
$vendor_tcp_ports{"Dell"}       = "1278,1279,2606,2607,3269,3668,3669,5869,5981,8192";


#
# from http://www.softpanorama.org/Hardware/HP/ILO/ilo3_tcp_ports.shtml
# and... /etc/services
#
# All iLO 3:
#
# UDP
#
#  1188 = HP Web Admin (hp-webadmin     1188/udp  # HP Web Admin)
#
# TCP
#
#  1188 = HP Web Admin (hp-webadmin     1188/tcp  # HP Web Admin)
#  3002 = Raw Serial Data
#  3389 = Terminal Services
#  9300 = Shared Remote Console
# 17988 = virtual media
# 17990 = remote console
$vendor_tcp_ports{"HP"}         = "1188,3002,3389,9300,17988,17990"; 
$vendor_udp_ports{"HP"}         = "1188";


# my box is supermicro... not sure what the fuck all these ports do, 
# but they're open....
$vendor_tcp_ports{"Supermicro"} = "555,4988,5120,5123,50000,8889,17990";
$vendor_udp_ports{"Supermicro"} = "1900";

# oracle/sun stuff
$vendor_tcp_ports{"Sun"} = "5120";

# add defaults
$all_IPMI_udp_ports = $vendor_udp_ports{"generic"};
$all_IPMI_tcp_ports = $vendor_tcp_ports{"generic"};

print "base UDP ports to scan: $all_IPMI_udp_ports\n" if $verbose;
print "base TCP ports to scan: $all_IPMI_tcp_ports\n" if $verbose;


#
# banners... regular expressions and bonus points if they match
#
# first guesses, obv need tuning
#

# regexps with associated vendor
# $vendor_banners{"Lights.?Out"} = "HP";
# $vendor_banners{"iLO"}         = "HP";
# $vendor_banners{"DRAC"}        = "Dell";
$vendor_banners{"HP"}   = "Lights.?Out";
$vendor_banners{"iLO"}  = "iLO";
$vendor_banners{"DRAC"} = "DRAC";

#
# ennumerate all the vendors from above... would do this manually
# above, but I don't trust myself to keep it all in sync
#
for $v (keys %vendor_tcp_ports) {
   # print "VT/tcp: $v\n";
   # push(@all_vendors, $v);
   $all_vendors{$v}++;
   @ports = split(/,/, $vendor_tcp_ports{$v});
   for $p (@ports) {
      if (defined($all_vendor_ports{$p}{"tcp"})) {
         $all_vendor_ports{$p}{"tcp"} .= ",$v";
      }
      else {
         $all_vendor_ports{$p}{"tcp"} = $v;
      }
      # print "XX ($p/tcp): $all_vendor_ports{$p}{'tcp'}\n";

      # print "\txxxxx: $v / tcp / $p\n";
      $_vpp{$v}{"tcp"}{$p}++;

   }
}

for $v (keys %vendor_udp_ports) {
   # print "VT/udp: $v\n";
   # push(@all_vendors, $v);
   $all_vendors{$v}++;
   @ports = split(/,/, $vendor_udp_ports{$v});
   for $p (@ports) {
      if (defined($all_vendor_ports{$p}{"udp"})) {
         $all_vendor_ports{$p}{"udp"} .= ",$v";
      }
      else {
         $all_vendor_ports{$p}{"udp"} = $v;
      }
      # print "YY ($p/udp): $all_vendor_ports{$p}{'tcp'}\n";

      # print "\tyyyyy: $v / udp / $p\n";
      $_vpp{$v}{"udp"}{$p}++;

   }
}

# for $porty (keys %all_vendor_ports) {
#    print "port $porty:\n";
#    for $proto (keys %{$all_vendor_ports{$porty}}) {
#       print "\t$proto:\t$all_vendor_ports{$porty}{$proto}\n";
#    }
# }

#
# add up ALL the vendor ports, or split the vendors added from command line
#
if ($ALL_vendors) {
   print "Adding all vendor specific checks...\n" if $verbose;
   #  @vendors = @all_vendors;
   for $vendor (keys %all_vendors) {
      push(@vendors, $vendor);
   }
}
else {
   @vendors = split(/,/, $vendors);
}

#
# add all vendor the ports to tcp or udp
#
for $vendor (@vendors) {

   # print "V: $vendor\n";

   if (!defined($vendor_udp_ports{$vendor}) && !defined($vendor_tcp_ports{$vendor})) {
      warn "Warning: no vendor specific data for $vendor\n";
   }

   else {

      #
      # tracking vendor/port ties, so we can potentially figure out the vendor maker from the ports....
      #
      add_to_vp_count($vendor);

      if (defined($vendor_udp_ports{$vendor})) {
         $tmp_udp = $vendor_udp_ports{$vendor};
         $all_IPMI_udp_ports .= ",$tmp_udp";
         print "\tadding vendor $vendor UDP ports: $tmp_udp\n" if ($verbose);
      }

      if (defined($vendor_tcp_ports{$vendor})) {
         $tmp_tcp = $vendor_tcp_ports{$vendor};
         $all_IPMI_tcp_ports .= ",$tmp_tcp";
         print "\tadding vendor $vendor TCP ports: $tmp_tcp\n" if ($verbose);
      }
   }
}

print "all UDP ports to scan: $all_IPMI_udp_ports\n" if $verbose;
print "all TCP ports to scan: $all_IPMI_tcp_ports\n" if $verbose;

#
# if both are true they'll cancel each other out, but checked for both active 
# up in options area
#
if ($scan_tcp) {
   $all_IPMI_udp_ports = "";
   print "\tclearing all UDP ports because of -tcp option\n" if $verbose;
}
if ($scan_udp) {
   $all_IPMI_tcp_ports = "";
   print "\tclearing all TCP ports because of -udp option\n" if $verbose;
}

#
# shouldn't happen, but... lots of things shouldn't....
#
die "no ports were specified... nothing to scan, bailin'\n" if ($all_IPMI_udp_ports eq "" && $all_IPMI_tcp_ports eq "");

# return($all_IPMI_udp_ports, $all_IPMI_tcp_ports, %all_vendor_ports);


#
# track all the vendor-to-port relationships
#
sub add_to_vp_count {
local($vendor) = @_;
local(@ports,%counted);

   print "sucking up $vendor ports...\n" if $verbose;

	if (defined($vendor_tcp_ports{$vendor})) {
	   @ports = split(/,/, $vendor_tcp_ports{$vendor});
	   for $port (@ports) {
	      $ports_n_vendors{$vendor}{"tcp"}{$port}++;
	   }
	}

	if (defined($vendor_udp_ports{$vendor})) {

	   @ports = split(/,/, $vendor_udp_ports{$vendor});
	   for $port (@ports) {
	      $ports_n_vendors{$vendor}{"udp"}{$port}++;
	   }
	}

}

1;
