#
#  Weights - these #'s determine how IPMI-ish a host is.  You can never be
#  sure (firewalls, temporarily down, weird network configurations and routing,
#  etc., etc.) , but some things count more than others.  The higher the number
#  the more in contributes to the overall score.
#

#
# some ports do double duty - just a web server on an odd port is obviously not 
# a sign of IPMI, but it's an indicator (banners will be checked as well.)
# Will probably change things over time as I get more data, this is for starters.
#

# 
$weight_common  = 0.1;
$weight_unusual = 1;
$weight_the_one = 5;

# if you don't specify a weight, it's treated as some trashy common port, so put it
$weight_unknown = $weight_common;


%weight_port = (
   'tcp' => {

   # more unusual/interesting ports
     555, $weight_unusual,
     623, $weight_unusual,
    1188, $weight_unusual,    # hp-webadmin
    1278, $weight_unusual,
    1279, $weight_unusual,
    2606, $weight_unusual,
    2607, $weight_unusual,
    3002, $weight_unusual,
    3389, $weight_unusual,
    3668, $weight_unusual,
    3669, $weight_unusual,
    4988, $weight_unusual,
    5120, $weight_unusual,
    5869, $weight_unusual,
    5981, $weight_unusual,
    5123, $weight_unusual,
    8192, $weight_unusual,
    8889, $weight_unusual,
    9300, $weight_unusual,
   17988, $weight_unusual,
   17990, $weight_unusual,
   50000, $weight_unusual
   
   },

   'udp' => {
   # the one and only
     623, $weight_the_one,
   # various others
     624, $weight_unusual,
    1278, $weight_unusual,
    1279, $weight_unusual,
    1900, $weight_unusual,
    2606, $weight_unusual,
    2607, $weight_unusual,
    3668, $weight_unusual,
    4995, $weight_unusual,
    5900, $weight_unusual
   }

);

#	
#	
# multipliers
$weight_state{"open"}             =  2;
$weight_state{"open|filtered"}    =  0.3;
# not sure what to do on this; need to understand output better (yes, I know what TCPW are!)
$weight_state{"tcpwrapped"}       =  0.1;
$weight_state{"filtered"}         =  0.2;   # wish I could trust this more, but....
$weight_state{"closed|filtered"}  =  0;     # any diff from closed?
$weight_state{"closed"}           =  0;

#
# banners... regular expressions and bonus points if they match
#
# first guesses, obv need tuning

for $v (keys %vendor_banners) {
   $ipmi_banners{$vendor_banners{$v}} = 10;
}

# $ipmi_banners{"Lights.?Out"}      = 10;
# $ipmi_banners{"iLO"}              = 10;  # HP's IPMI
# $ipmi_banners{"DRAC"}             = 10;  # Dell's IPMI

# not too uncommon embedded linuxy system thingy: but used on at least on some
# supermicro ssh's
$ipmi_banners{"[Dd]ropbear"}      =  5;
# generic hopeful catch
$ipmi_banners{"[Ii][Pp][Mm][Ii]"} = 10;

# bonus points for...

# this is a no-thought scan through output nmap can't figure out
$weight_sucking_fingers           =  3;

# if ipmiping works, probably is IPMI....!
$ipmi_ping_success                = 40;


#
# if greater than this number, will match
#
$ipmi_cutoff{"yes"}               = 15;
$ipmi_cutoff{"maybe"}             =  3;

1;

