ohrwurm-0.1 - an RTP fuzzer

(c) 2006 by Matthias Wenzel

LICENSE
~~~~~~~
GPLv2
see http://www.gnu.org/copyleft/gpl.html

INSTALLATION
~~~~~~~~~~~~
type "make", hit return.
report errors to ohrwurm/at/mazzoo/dot/de
ohrwurm requires libpcap.

RUNNING
~~~~~~~
before starting ohrwurm you need to run arpspoof. arpspoof is a part of the
dsniff package from http://www.monkey.org/~dugsong/dsniff/
Say you want to fuzz the RTP communication between two boxes A and B in your
LAN, with the IPs 192.168.0.11 and 192.168.0.22 .
Now on a third box e.g. 192.168.0.33 start arpspoof twice (in two terminals):

arpspoof 192.168.0.11
arpspoof 192.168.0.22

on the same box 192.168.0.33 start ohrwurm with the IP addresses of A and B:
ohrwurm -a 192.168.0.11 -b 192.168.0.22

Now start a SIP based audio call between A and B. The RTP stream will be
fuzzed. When you're done press CTRL-C in the terminals.
Other options can be seen when running ohrwurm without any arguments.

ohrwurm?
~~~~~~~~
ohrwurm is german and translates to earwig. So it's something nasty you don't
get rid of easily. Literally translated ohrwurm means earworm.

SUCCESS
~~~~~~~
As of August 2006 ohrwurm broke the following applications/transports:
 - linphonec 1.10 / iLBC (stops sending RTP, no crash)
 - linphonec 1.10 / iLBC (re-negotiates PCMA via SIP, but continues sending
   iLBC)
 - Fritz! box 7050 / iLBC (stops sending RTP, no crash)
 - Cisco 7905 crashes with arpspoof alone :(


please report anything ohrwurm broke to ohrwurm/at/mazzoo/dot/de, even if it
was a famous packet sniffer ;)

BUGS/TODO
~~~~~~~~~
 - fuzzing:
   - reorder/drop/inject packets
   - change packet length
 - save packets in pcap(tcpdump) format
 - support variable length IP headers
 - support variable length RTP headers
 - support SIP ports other than 5060
 - support multiple calls
 - do we really need to memcpy() eack packet?
 - figure out local mac address differently (ifr)
 - fill ow.rawsock_sa.sll_halen=ETH_ALEN (required??)
 - fill ow.rawsock_sa.sll_addr according to packet(7) (required??)
 - support unidirectional fuzzing
 - support RTCP fuzzing
 - support other media types than "audio" ("video", "application", "data" and
   "control", as per rfc2327), e.g. "m=application 32416 udp"
 - do arpspoof ourself
 - non-LAN, GW and router operation

