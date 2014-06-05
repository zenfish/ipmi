<p>
I wrote some software to explore IPMI; here are some of results.  I thought I'd 
do the usual detect, get data, and audit sort of cycle.  Each of these turned
out to be fairly interesting problem on its own, at least to me.

</p> <p>

<h4>Password Cracking</h4>

Here's a <a href="rak-the-ripper.pl"> little Perl program</a> 
that tries to guess an account on a remote BMC, extract its hash,
and then try to crack its (HMAC hashed) password.  I wrote up a
<a href="http://fish2.com/ipmi/remote-pw-cracking.html">little</a>
bit on this for the curious.  Heavily commented, it may provide some utility.

<h4> Get ciphers</h4>

The IPMI spec says that you can get a remote system's cipher without any
authentication, but I'm not aware of any tool that actually does this
(they all require auth, although of course you could input the raw hex
bytes if you wanted!)  So I wrote this little one to do so; it mostly
tries to follow the ipmitool output; in doing so I believe I found a
bug in that utility (in the final line *sometimes* systems emit some 
garbage that appears to be misinterpreted), but who knows, I don't have
enough systems to test.  Anyway...  <a href="ipmi-get-ciphers.py">ipmi-get-ciphers.py</a>.

If nothing else, useful for spotting Cipher0 systems (note - this
merely points out ciphers that are supported - it doesn't mean that
they're actually turned on), but there are interesting things out in
the wild.


<h4> Dump passwords from a SuperMicro binary password file</h4>

Supermicro has had some issues with password file disclosure from
their BMC - for instance, see this and other write-ups:

<blockquote>
     <a href="https://community.rapid7.com/community/metasploit/blog/2013/07/02/a-penetration-testers-guide-to-ipmi">a-penetration-testers-guide-to-ipmi</a>
</blockquote>

To use this script simply say:


<blockquote>
    Usage: <a href="dump_SM.py">dump_SM.py</a> password_file
</blockquote>


Works for me, no warranty implied, guaranteed, etc.

<h4>Detection</h4>

Well, if you can talk to UDP port 623, it's pretty simple
to find out if a remote system is running IPMI.  Unless you're inside
a data center, however, most folks block UDP.  And even if they
don't... UDP scanning is about as slow as can be imagined.  So I'm
currently using two basic methods, leveraging the venerable Nmap and
ipmiping (from the FreeIPMI Gnu tools.)  The easiest thing to do is:

</p> <p>

<ul>
<li>Use ipmiping to ask a remote system if it speaks IPMI or not.  A positive
    response is the strongest indication that a system speaks IPMI
    (but nothing is certain!) More technically it sends two IPMI
    Get Channel Authentication Capabilities calls via a Get Channel
    Authentication Capabilities request datagram on UDP port 623 (two
    requests since it's using UDP, and connections aren't guaranteed.)

    </p> <p>

    Since Nmap is far more efficient at scanning large scale networks
    than ipmiping this method is only used if Nmap says that a hosts
    has UDP 623 open.

    </p> <p>

    For better or worse this port is often blocked, so much of the
    time other methods are more likely to find out obliquely whether
    or not IPMI is running.

<li>The second method is a bit squishy, and relies on a bit of
    induction (aka guessing.) Nmap scans ports that are known to be
    associated with IPMI and vendor additions; UDP 623 is obvious (the
    default IPMI port), but there are a variety of ports (both UDP and
    TCP) that by themselves might not immediately give you an answer,
    but when taken as a whole can strongly indicate its presence.
    TFTP, SNMP, SSH/SMASH, VNC, and many others are among these.

    </p> <p>

    Ports are weighted by their indicative ability and whether or not
    Nmap finds them open, filtered, or in other states.

    </p> <p>

    Nmap also can show the banners of services connected to.  I use
    regular expressions to hunt for targets - for instance the strings
    "iLO" and "DRAC" are good indicators that a system might be running
    HP's Integrated Lights Out service, or iLO.

    </p> <p>

    <strong>Note:</strong> Currently I do NOT use the broadcast
    ping method (a very quick way to zip through the subnet you're
    residing in); I simply don't have any data on the effectiveness
    on this; while very fast when it works I didn't feel like it
    allowed for the control and reliability of arbitrary scans.
    Two out of three of my systems (Dell and HP) responded to an
    RMCP ping.  None responded to a broadcast ping by idiscover
    (ipmiutil discover.)  All did, however, respond to my Python
    audit tool below.

    </p> <p>

    Unfortunately (of course!) the spectre of communications and
    networks comes into play -  nmap gives a bunch of different reasons
    as to why a port is open or not (open, closed, filtered, etc.)
    Yet another table has a set of weights that gives more points to
    an open port than to a "open|filtered" (as Nmap might say) hit.
    Interpreting nmap and weighting is a bit on the frustrating side,
    but c'est la vie.


    </p> <p>

    Take all the weights, add up all the points and you have an IPMI
    certainty level.  I've found in ad hoc testing that 15 points or
    more are strong indicators that the system is running IPMI.

    </p> <p>

    Currently I have various thresholds (no, possibly, probably,
    yes.) In tests - without having known access to any other servers
    than my own - it seems to work reasonably well.  That is,
    the things that I think are suspicious and my basic thought
    model above does indeed bubble certain servers to the top and
    leaves random hosts alone.  There are some real problems with
    false positives, tho - many firewalls seem to imply to nmap that
    there's something on any port (I've thought of tossing in a rare
    port or two (if you listen to something like port 1 & 31313,
    for instance, you're probably not *really* listening to it!)

    </p> <p>

    But this isn't meant to be the last word on the topic.  It should
    be fairly simple to get some decent data on IPMI banners, my
    guess is that it'd be by far the best way to rapidly scan large
    amounts of systems.

</ul>
</p> <p>

Here are four pieces of Perl to implement the above; one scans,
one interprets, and the other two are used for weighting.  It's a
research tool or a proof of concept, not a production scanner, but
it does produce some reasonable output.


</p> <p>

<strong>REQUIRED: Nmap version 6.</strong>

</p>

<table border=1>
<tr> <td style="padding-left:30px;"> <span> <a href="ipmi-scan/ipmi_scan.pl">ipmi_scan.pl</a> - basic IPMI scanner, uses Nmap and, if available, ipmitool </span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span> <a href="ipmi-scan/ipmi_scan.out">ipmi_scan man page</a> - man page for above</span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span> <a href="ipmi-scan/post_ipmi_scan.pl">post_ipmi_scan.pl</a> - parses the output of above, spits out some weighted results </span></td> </tr>
<tr> <td style="padding-left:30px;"> <span><a href="ipmi-scan/j_vendor.pl">j_vendor.pl</a> - Some basic vendor data... which use which ports?</span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span><a href="ipmi-scan/j_weights.pl">j_weights.pl</a> - Some basic vendor weights for above</span> </span></td> </tr>
</table>

</p> <p>

Usage is pretty simple, if a bit quirky. Should be run as root. Verbose (-v) for lots of output.
<blockquote>
<pre>
# standard run:
   ./ipmi_scan.pl -A -v -O yes  192.168.0.0/24
# fast
   ./ipmi_scan.pl -tcp -v 192.168.0.0/24
# kitchen sink
   ./ipmi_scan.pl -A -v -O high 192.168.0.0/24
</pre>
</blockquote>
The scan will create a pair of result files that correspond to the
target names (slashes are converted to underscores.) Simply run the
post-processor on them; tossing through reverse numeric sort puts them
in a more interesting order.  Anything over 10 I'd call suspicious,
where greater than 20 is pretty certain to be running IPMI.  

In this case I
used the terse flag (-t) to cut the output to the bare minimum.

<blockquote>
<pre>
./post_ipmi_scan.pl -t 192.168.0.0_24|sort -rn
96.3 192.168.0.69
16.25 192.168.0.46
10.8 192.168.0.23
7.33 192.168.0.202
5.4 192.168.0.189
5.4 192.168.0.179
1.7 192.168.0.9
1.23 192.168.0.1
1.1 192.168.0.8
0.9 192.168.0.251
0.63 192.168.0.55
0.43 silent/192.168.0.250
0.2 pi.fish2.com/192.168.0.14
0.2 fierce.fish2.com/192.168.0.6
0.2 192.168.0.88
0.01 192.168.0.16
</pre>
</blockquote>
</p> <p>
In the above results the top 3 systems are actually running IPMI,
but only the HP told Nmap that UDP port 623 was open - my Dell and
Supermicro returned the more ambiguous "open|filtered" response,
which is quite commonly a false alarm, bleah.  Perhaps it's better
just to suck it up and do the IPMI ping in parallel with the scanner
(or write an NSE to do it correctly in Nmap.)

</p> <p>
<h4>Audit</h4>

Two programs here, one is a simple Python
remote prober (starting to hate Perl, let me tell you) and a second
that uses utilities from <a href="http://www.gnu.org/software/freeipmi/">FreeIPMI</a>
to grab credentialed configuration data.

</p> <p>

A small python program (over 50% inline comments, 2.5k gzip'd) that sends a single packet 
to a BMC and mulls over the response.  What can you do with only a single packet, one 
might ask?  10+ different security tests for IPMI, for starters.  Well, for starters 
and for enders, it's only a packet :)  Requires python, a BMC and an open path to 
UDP port 623 to work.  Usage is simply "ipmi-get-auth.py target".

<p style="padding-left:60px;">
   <span style="padding: 5px; border: 1px solid #AAA;"> <a href="ipmi-get-auth.py">ipmi-get-auth.py</a> /
   <a href="http://trouble.org/?p=712">A very small description</a> </span><br />
</p> <p>

Here's a couple of small python programs that - using FreeIPMI tools - (a) sucks in the
basic IPMI/BMC configuration of a server and (b) does a lil' security check on the results.

Because I... well, no good reason, actually.  One is in python3 and the
other in python2. I guess I'm testing your readiness. The programs are
pretty heavily commented, especially ipmifreely.py, so check that for
more details on what's going on.  Requires simplejson and ConfigParser,
maybe some more.

</p> <p>

<span style="color: #ff0000;">YOU MUST</span> have <a title="FreeIPMI"
href="www.gnu.org/software/freeipmi/" target="_blank">FreeIPMI</a>
installed, which, as of this writing, kills off Mac and Windows chances
at sucking down a cool JSON file from a server. And you really,
really should have a recent version.  Don't say I didn't warn you.
But life goes on.

</p> <p>

The data aquisition is done via a python program (I-check.py) that
requires valid credentials to get data. It converts the results to
JSON, which in turn may be checked by the audit tool (ipmifreely.py.)
There is a sample policy in "IPMI-policy.ini", where I put some values
for testing.

</p> <p>

<table border=1>
<tr> <td style="padding-left:30px;"> <span> <a href="iaudit/I-check.py">I-check.py</a> - grabs IPMI configuration data</span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span> <a href="iaudit/ipmifreely.py">ipmifreely.py</a> - parses the output of above, spits out some results</span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span> <a href="iaudit/IPMI-policy.ini">IPMI-policy.ini</a> - IPMI policy file</span></td> </tr>
</table>

</p> <p>

Sample use:

<blockquote>
<pre>
# this grabs the configuration stuff; here I'm using it on an HP iLO 3 server
# the output is redirected to a file
$ ./ipmifreely.py -v -u admin -p admin 192.168.0.46 &gt; hp.json
# This takes the JSON file and looks for issues
$ ./I-check.py drac.json
./I-check.py hp.json 
Host:    192.168.0.46
[bmc-config]   Serial_Channel Non_Volatile_Enable_Pef_Alerting = No
[bmc-config]   Serial_Channel Volatile_Enable_Pef_Alerting  = No
[bmc-config]   Serial_Channel Volatile_Enable_Per_Message_Auth = No
[bmc-config]   Serial_Channel Non_Volatile_Enable_Per_Message_Auth   = No
[bmc-config]   Lan_Conf_Security_Keys  K_G   = 0x0000000000000000000000000000000000000000
[bmc-config]   SOL_Conf Force_SOL_Payload_Authentication = No
[bmc-config]   SOL_Conf Force_SOL_Payload_Encryption  = No
[bmc-config]   Lan_Conf_Auth  Callback_Enable_Auth_Type_None   = Yes
[bmc-config]   Lan_Conf_Auth  Operator_Enable_Auth_Type_None   = Yes
[bmc-config]   Lan_Conf_Auth  OEM_Enable_Auth_Type_None  = Yes
[bmc-config]   Lan_Conf_Auth  Admin_Enable_Auth_Type_None   = Yes
[bmc-config]   Lan_Conf_Auth  User_Enable_Auth_Type_None = Yes
[bmc-config]   Rmcpplus_Conf_Privilege Maximum_Privilege_Cipher_Suite_Id_1 = OEM_Proprietary
[bmc-config]   Rmcpplus_Conf_Privilege Maximum_Privilege_Cipher_Suite_Id_0 = OEM_Proprietary
[bmc-config]   Rmcpplus_Conf_Privilege Maximum_Privilege_Cipher_Suite_Id_2 = OEM_Proprietary
[pef-config]   Community_String  Community_String  = public
[pef-config]   PEF_Conf Enable_PEF_Event_Messages  = No
</pre>
</blockquote>

You can check out some <a href="/ipmi/bp.pdf">IPMI Security Best Practices</a> for more
on what to check what I consider to be good things to do, security-wise.

