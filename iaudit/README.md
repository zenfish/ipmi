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
   <span style="padding: 5px; border: 1px solid #AAA;"> <a href="../ipmi-get-auth.py">ipmi-get-auth.py</a> /
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
<tr> <td style="padding-left:30px;"> <span> <a href="I-check.py">I-check.py</a> - grabs IPMI configuration data</span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span> <a href="ipmifreely.py">ipmifreely.py</a> - parses the output of above, spits out some results</span> </td> </tr>
<tr> <td style="padding-left:30px;"> <span> <a href="IPMI-policy.ini">IPMI-policy.ini</a> - IPMI policy file</span></td> </tr>
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

